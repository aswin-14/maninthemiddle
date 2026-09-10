"""PyQt5 dashboard for the netmon Engine."""
import csv
import os
import time

from PyQt5 import QtCore, QtGui, QtWidgets

from .engine import Engine
from . import spoof


def human_bytes(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or u == "TB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def human_rate(bps):
    return human_bytes(bps) + "/s"


def ago(ts):
    s = int(time.time() - ts)
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s//60}m ago"
    return f"{s//3600}h ago"


DARK = """
QWidget { background:#0f141b; color:#d7dee8; font-size:13px; }
QLabel#h1 { font-size:18px; font-weight:bold; color:#eef3f9; }
QLabel#meta { color:#7f8ea3; }
QTableWidget { background:#131a23; gridline-color:#22303f; border:1px solid #22303f; }
QHeaderView::section { background:#1b2530; color:#9fb0c3; padding:6px; border:0; font-weight:bold; }
QTableWidget::item:selected { background:#1f6feb; color:white; }
QPushButton { background:#1f6feb; color:white; border:0; padding:7px 14px; border-radius:5px; font-weight:bold; }
QPushButton:disabled { background:#2b3644; color:#6b7889; }
QPushButton#ghost { background:#22303f; color:#cdd8e5; }
QTextEdit { background:#131a23; border:1px solid #22303f; }
QGroupBox { border:1px solid #22303f; border-radius:6px; margin-top:10px; font-weight:bold; color:#9fb0c3; }
QGroupBox::title { subcontrol-origin:margin; left:10px; padding:0 4px; }
"""


class ScanThread(QtCore.QThread):
    done = QtCore.pyqtSignal()

    def __init__(self, engine):
        super().__init__()
        self.engine = engine

    def run(self):
        try:
            self.engine.arp_scan()
        except Exception:
            pass
        self.done.emit()


class PortScanThread(QtCore.QThread):
    done = QtCore.pyqtSignal(object)

    def __init__(self, engine, ip):
        super().__init__()
        self.engine = engine
        self.ip = ip

    def run(self):
        res = self.engine.port_scan(self.ip)
        self.done.emit(res)


class Dashboard(QtWidgets.QMainWindow):
    def __init__(self, iface):
        super().__init__()
        self.engine = Engine(iface)
        self.selected_mac = None
        self.spoofer = None
        self.setWindowTitle(f"netmon — network monitor ({iface})")
        self.resize(1180, 720)
        self.setStyleSheet(DARK)
        self._build()
        self.engine.start()
        self._kick_scan()
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1500)

    # ---- layout ----------------------------------------------------------
    def _build(self):
        cw = QtWidgets.QWidget(); self.setCentralWidget(cw)
        root = QtWidgets.QVBoxLayout(cw)

        # header
        head = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("netmon"); title.setObjectName("h1")
        self.meta = QtWidgets.QLabel("starting…"); self.meta.setObjectName("meta")
        head.addWidget(title); head.addSpacing(14); head.addWidget(self.meta); head.addStretch()
        self.btn_intercept = QtWidgets.QPushButton("Intercept selected")
        self.btn_intercept.clicked.connect(self.toggle_intercept)
        self.btn_scan = QtWidgets.QPushButton("Rescan devices")
        self.btn_scan.clicked.connect(self._kick_scan)
        self.btn_export = QtWidgets.QPushButton("Export CSV"); self.btn_export.setObjectName("ghost")
        self.btn_export.clicked.connect(self.export_csv)
        head.addWidget(self.btn_intercept); head.addWidget(self.btn_scan); head.addWidget(self.btn_export)
        root.addLayout(head)

        self.intercept_bar = QtWidgets.QLabel("")
        self.intercept_bar.setStyleSheet("background:#3a2d0a;color:#ffe08a;padding:5px;")
        self.intercept_bar.hide()
        root.addWidget(self.intercept_bar)

        # splitter: devices table | detail
        split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        cols = ["", "IP", "Hostname / MAC", "Vendor", "Upload", "Download",
                "Total", "Seen"]
        self.table = QtWidgets.QTableWidget(0, len(cols))
        self.table.setHorizontalHeaderLabels(cols)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        h = self.table.horizontalHeader()
        h.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
        h.setSectionResizeMode(3, QtWidgets.QHeaderView.Stretch)
        self.table.setColumnWidth(0, 24)
        self.table.itemSelectionChanged.connect(self._on_select)
        split.addWidget(self.table)

        # detail panel with tabs
        det = QtWidgets.QWidget(); dl = QtWidgets.QVBoxLayout(det)
        drow = QtWidgets.QHBoxLayout()
        self.det_title = QtWidgets.QLabel("Select a device"); self.det_title.setObjectName("h1")
        drow.addWidget(self.det_title); drow.addStretch()
        self.btn_ports = QtWidgets.QPushButton("Scan ports"); self.btn_ports.setObjectName("ghost")
        self.btn_ports.clicked.connect(self.scan_ports)
        drow.addWidget(self.btn_ports)
        dl.addLayout(drow)

        self.tabs = QtWidgets.QTabWidget()
        self.t_sites = QtWidgets.QTextEdit(); self.t_sites.setReadOnly(True)
        self.t_http = QtWidgets.QTextEdit(); self.t_http.setReadOnly(True)
        self.t_ports = QtWidgets.QTextEdit(); self.t_ports.setReadOnly(True)
        self.t_conns = QtWidgets.QTextEdit(); self.t_conns.setReadOnly(True)
        self.tabs.addTab(self.t_sites, "Websites")
        self.tabs.addTab(self.t_http, "HTTP (plaintext)")
        self.tabs.addTab(self.t_ports, "Open ports")
        self.tabs.addTab(self.t_conns, "Connections")
        dl.addWidget(self.tabs)
        split.addWidget(det)
        split.setSizes([620, 560])
        root.addWidget(split, 3)

        # global security-alerts panel
        gb_al = QtWidgets.QGroupBox("Security alerts — unencrypted traffic & exposed credentials")
        avl = QtWidgets.QVBoxLayout(gb_al)
        self.alerts = QtWidgets.QTextEdit(); self.alerts.setReadOnly(True)
        self.alerts.setMinimumHeight(120)
        avl.addWidget(self.alerts)
        root.addWidget(gb_al, 1)

        if os.geteuid() != 0:
            bar = QtWidgets.QLabel("  ⚠  Not running as root — packet capture is "
                                   "disabled. Restart with sudo for live traffic.")
            bar.setStyleSheet("background:#5a1e1e;color:#ffd7d7;padding:6px;")
            root.addWidget(bar)

    # ---- actions ---------------------------------------------------------
    def _kick_scan(self):
        self.btn_scan.setEnabled(False); self.btn_scan.setText("Scanning…")
        self.scan = ScanThread(self.engine)
        self.scan.done.connect(self._scan_done)
        self.scan.start()

    def _scan_done(self):
        self.btn_scan.setEnabled(True); self.btn_scan.setText("Rescan devices")
        self.refresh()

    # ---- MITM intercept --------------------------------------------------
    def _selected_devices(self):
        """Return [{ip, mac, name}] for the currently selected rows."""
        out = []
        for idx in self.table.selectionModel().selectedRows(column=1):
            mac = self.table.item(idx.row(), 1).data(QtCore.Qt.UserRole)
            r = getattr(self, "_rows", {}).get(mac)
            if r and r.get("ip") and r.get("mac"):
                out.append({"ip": r["ip"], "mac": r["mac"],
                            "name": r["hostname"] or r["ip"]})
        return out

    def toggle_intercept(self):
        if self.spoofer and self.spoofer.running:
            self.stop_intercept()
        else:
            self.start_intercept()

    def start_intercept(self):
        if os.geteuid() != 0:
            QtWidgets.QMessageBox.warning(self, "Intercept",
                "Root is required. Restart with sudo.")
            return
        targets = self._selected_devices()
        if not targets:
            QtWidgets.QMessageBox.information(self, "Intercept",
                "Select one or more devices in the table first.")
            return
        names = ", ".join(t["name"] for t in targets)
        ok = QtWidgets.QMessageBox.question(
            self, "Intercept traffic",
            f"Route these devices' traffic through this machine via ARP?\n\n"
            f"  {names}\n\n"
            "This is an active MITM technique — use ONLY on a network you own or "
            "are authorized to test. IP forwarding will be enabled so the devices "
            "keep working, and ARP tables are restored when you stop.\n\nProceed?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No)
        if ok != QtWidgets.QMessageBox.Yes:
            return

        gw_ip = spoof.default_gateway(self.engine.iface)
        gw_mac = spoof.mac_of(gw_ip, self.engine.iface) if gw_ip else ""
        if not gw_ip or not gw_mac:
            QtWidgets.QMessageBox.critical(self, "Intercept",
                f"Could not resolve the gateway (ip={gw_ip or '?'}, mac={gw_mac or '?'}).")
            return

        self.spoofer = spoof.ArpSpoofer(self.engine.iface, gw_ip, gw_mac)
        self.spoofer.set_targets(targets)
        self.spoofer.start()
        self.btn_intercept.setText("Stop intercept")
        self.btn_intercept.setStyleSheet("background:#d9534f;")
        self.intercept_bar.setText(
            f"  ⚡ Intercepting {len(targets)} device(s) via gateway {gw_ip} — "
            f"IP forwarding ON. Their traffic now flows through this machine.")
        self.intercept_bar.show()

    def stop_intercept(self):
        if self.spoofer:
            self.spoofer.stop()
            self.spoofer = None
        self.btn_intercept.setText("Intercept selected")
        self.btn_intercept.setStyleSheet("")
        self.intercept_bar.hide()

    def _on_select(self):
        row = self.table.currentRow()
        if row < 0:
            return
        it = self.table.item(row, 1)
        if it:
            self.selected_mac = it.data(QtCore.Qt.UserRole)
            self.refresh_detail()

    # ---- refresh ---------------------------------------------------------
    def refresh(self):
        rows, meta = self.engine.snapshot()
        self._rows = {r["mac"]: r for r in rows}
        self.meta.setText(
            f"iface {meta['iface']}  •  {meta['local_ip']}  •  net {meta['net']}  •  "
            f"{meta['devices']} devices  •  {meta['pkts']:,} packets  •  up {meta['uptime']}s")
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            dot = "🟢" if r["online"] else "⚪"
            name = r["hostname"] or r["mac"]
            vals = [dot, r["ip"] or "—", name, r["vendor"] or "—",
                    human_rate(r["up"]), human_rate(r["down"]),
                    human_bytes(r["tx"] + r["rx"]), ago(r["last_seen"])]
            for c, v in enumerate(vals):
                item = QtWidgets.QTableWidgetItem(str(v))
                if c == 1:
                    item.setData(QtCore.Qt.UserRole, r["mac"])
                if c in (4, 5, 6):
                    item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
                self.table.setItem(i, c, item)
        # keep selection
        if self.selected_mac:
            for i in range(self.table.rowCount()):
                it = self.table.item(i, 1)
                if it and it.data(QtCore.Qt.UserRole) == self.selected_mac:
                    self.table.selectRow(i); break
        self._render_alerts(meta.get("alerts", []))
        self.refresh_detail()

    _SEV = {"critical": "🔴", "warn": "🟠", "info": "🔵"}

    def _render_alerts(self, alerts):
        if not alerts:
            self.alerts.setPlainText(
                "No unencrypted-traffic or credential findings yet.\n"
                "Alerts appear here when a device uses HTTP, Telnet, FTP, or sends "
                "credentials in the clear.")
            return
        lines = []
        for a in alerts:
            lines.append(f"{self._SEV.get(a['severity'],'•')} {time.strftime('%H:%M:%S', time.localtime(a['ts']))}  "
                         f"[{a['ip']}]  {a['kind']}: {a['detail']}")
        self.alerts.setPlainText("\n".join(lines))

    def refresh_detail(self):
        r = getattr(self, "_rows", {}).get(self.selected_mac)
        if not r:
            return
        self.det_title.setText(f"{r['hostname'] or r['ip'] or r['mac']}   "
                               f"({r['vendor'] or 'unknown vendor'})")

        # --- Websites tab: TLS SNI + HTTP Host, then DNS fallback ---
        parts = []
        if r["sites"]:
            parts.append("Sites actually contacted (TLS SNI / HTTP Host):")
            parts += [f"  {s['host']}   ×{s['hits']}" for s in r["sites"]]
            parts.append("")
        if r["domains"]:
            parts.append(f"DNS lookups ({r['dns_count']} total):")
            parts += [f"  {d}" for d in r["domains"]]
        if not parts:
            parts = ["No website activity captured from this device yet.",
                     "(You only see traffic that reaches this machine — run on the "
                     "router, use Intercept, or set this host as DNS server.)"]
        self.t_sites.setPlainText("\n".join(parts))

        # --- HTTP tab: full plaintext URLs ---
        if r["http"]:
            lines = [f"{time.strftime('%H:%M:%S', time.localtime(h['ts']))}  "
                     f"{h['method']:<5} {h['url']}"
                     + (f"\n        UA: {h['ua']}" if h['ua'] else "")
                     for h in r["http"]]
            self.t_http.setPlainText("\n".join(lines))
        else:
            self.t_http.setPlainText(
                "No plaintext HTTP seen. Modern sites use HTTPS, so most browsing "
                "won't appear here — only genuinely unencrypted HTTP does.")

        # --- Ports tab ---
        if r["open_ports"]:
            lines = [f"  {p['port']:>5}/tcp   {p['service']}" for p in r["open_ports"]]
            self.t_ports.setPlainText("Open ports on this device:\n" + "\n".join(lines))
        else:
            self.t_ports.setPlainText(
                "No open ports known yet. Click 'Scan ports' to actively probe this "
                "device with nmap, or ports appear passively when other hosts connect to it.")

        # --- Connections tab ---
        if r["peers"]:
            lines = [f"{p['ip']:<16}  {p['proto']:<4} {p['label']:<10}  {human_bytes(p['bytes'])}"
                     for p in r["peers"]]
            self.t_conns.setPlainText("\n".join(lines))
        else:
            self.t_conns.setPlainText("No connections captured yet.")

    def scan_ports(self):
        r = getattr(self, "_rows", {}).get(self.selected_mac)
        if not r or not r.get("ip"):
            QtWidgets.QMessageBox.information(self, "Scan ports", "Select a device first.")
            return
        ip = r["ip"]
        self.btn_ports.setEnabled(False); self.btn_ports.setText("Scanning…")
        self.tabs.setCurrentWidget(self.t_ports)
        self.t_ports.setPlainText(f"Running nmap against {ip} … (top 200 ports)")
        self.pscan = PortScanThread(self.engine, ip)
        self.pscan.done.connect(self._ports_done)
        self.pscan.start()

    def _ports_done(self, result):
        self.btn_ports.setEnabled(True); self.btn_ports.setText("Scan ports")
        if isinstance(result, dict) and result.get("error"):
            self.t_ports.setPlainText("nmap error: " + result["error"])
            return
        self.refresh_detail()

    def export_csv(self):
        rows, _ = self.engine.snapshot()
        path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Export devices", "netmon_devices.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ip", "mac", "hostname", "vendor", "online",
                        "tx_bytes", "rx_bytes", "packets", "dns_count",
                        "recent_domains"])
            for r in rows:
                w.writerow([r["ip"], r["mac"], r["hostname"], r["vendor"],
                            r["online"], r["tx"], r["rx"], r["packets"],
                            r["dns_count"], " ".join(r["domains"])])
        QtWidgets.QMessageBox.information(self, "Exported", f"Saved {len(rows)} devices to\n{path}")

    def closeEvent(self, e):
        # always heal the network before quitting
        if self.spoofer:
            try:
                self.spoofer.stop()
            except Exception:
                pass
        self.engine.stop()
        super().closeEvent(e)
