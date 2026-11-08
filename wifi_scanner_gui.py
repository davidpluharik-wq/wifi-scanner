#!/usr/bin/env python3
"""Standalone WiFi scanner with a local scanner implementation."""
import tkinter as tk
from tkinter import ttk
from wifi_ui import WifiScannerTab


def main():
    root = tk.Tk()
    root.title('WiFi Scanner')
    root.geometry('1100x650')
    ttk.Style(root).theme_use('clam')
    scanner = WifiScannerTab(root)
    scanner.frame.pack(fill='both', expand=True)

    def close():
        if scanner.scanner_thread:
            scanner.scanner_thread.stop()
        root.destroy()

    root.protocol('WM_DELETE_WINDOW', close)
    root.mainloop()


if __name__ == '__main__':
    main()
