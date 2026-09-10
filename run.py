#!/usr/bin/env python3
"""
netmon — GUI network monitor for a network you own/administer.

Usage:  sudo ./.venv/bin/python run.py [interface]
If no interface is given, it auto-picks the active one or shows a chooser.
"""
import os
import socket
import sys
import threading
import time

from PyQt5 import QtWidgets


def active_ifaces():
    from scapy.all import get_if_list, get_if_addr
    out = []
    for name in get_if_list():
        if name == "lo":
            continue
        try:
            ip = get_if_addr(name)
        except Exception:
            ip = "0.0.0.0"
        if ip and ip != "0.0.0.0":
            out.append((name, ip))
    return out


def pick_iface(app):
    ifs = active_ifaces()
    if len(ifs) == 1:
        return ifs[0][0]
    if not ifs:
        QtWidgets.QMessageBox.critical(None, "netmon", "No active network interface found.")
        sys.exit(1)
    items = [f"{n}  ({ip})" for n, ip in ifs]
    choice, ok = QtWidgets.QInputDialog.getItem(
        None, "netmon", "Choose the interface to monitor:", items, 0, False)
    if not ok:
        sys.exit(0)
    return ifs[items.index(choice)][0]


def hostname_resolver(engine):
    """Fill in device hostnames via reverse DNS, quietly, forever."""
    while True:
        try:
            with engine.lock:
                targets = [d for d in engine.devices.values() if d.ip and not d.hostname]
            for d in targets:
                try:
                    name = socket.gethostbyaddr(d.ip)[0]
                except Exception:
                    name = ""
                if name:
                    with engine.lock:
                        d.hostname = name
        except Exception:
            pass
        time.sleep(8)


def main():
    if os.geteuid() != 0:
        print("\n  netmon needs root for packet capture.")
        print("  Run:  sudo ./.venv/bin/python run.py\n")
        # still launch so the user sees the UI + warning banner
    app = QtWidgets.QApplication(sys.argv)
    iface = sys.argv[1] if len(sys.argv) > 1 else pick_iface(app)

    from netmon.gui import Dashboard
    win = Dashboard(iface)
    t = threading.Thread(target=hostname_resolver, args=(win.engine,), daemon=True)
    t.start()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
