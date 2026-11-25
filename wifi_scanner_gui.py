#!/usr/bin/env python3
"""Standalone WiFi scanner with a local scanner implementation."""
import tkinter as tk
from tkinter import ttk
from netsuite_theme import apply_theme, add_header
from wifi_ui import WifiScannerTab


def main():
    root = tk.Tk()
    root.title('WiFi Scanner')
    root.geometry('1100x820')
    add_header(root, 'WiFi Scanner')
    scanner = WifiScannerTab(root)
    scanner.frame.pack(fill='both', expand=True)
    apply_theme(root)

    def close():
        if scanner.scanner_thread:
            scanner.scanner_thread.stop()
        root.destroy()

    root.protocol('WM_DELETE_WINDOW', close)
    root.mainloop()


if __name__ == '__main__':
    main()
