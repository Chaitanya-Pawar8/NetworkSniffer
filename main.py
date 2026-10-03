#!/usr/bin/env python3
"""
Network Sniffer (Python + Scapy + Tkinter GUI)
For legal purposes only.

Run with elevated privileges (packet capture requires it):
    Windows : install Npcap (https://npcap.com) in "WinPcap API-compatible
              mode", then run PowerShell/CMD "as Administrator" and
              `python main.py`
    macOS   : sudo python3 main.py
    Linux   : sudo python3 main.py
              (install libpcap if missing: sudo apt install libpcap-dev)

If capture starts but no packets ever appear, see README.md ->
Troubleshooting.

Author: Chaitanya Pawar
"""

import ctypes
import os
import sys

from gui_app import launch


def _is_admin() -> bool:
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def main():
    if not _is_admin():
        print(
            "\n[!] Warning: raw packet capture usually needs administrator / root "
            "privileges.\n    If capture fails to start, re-run this script as "
            "admin/sudo.\n"
        )
    launch()


if __name__ == "__main__":
    sys.exit(main())
