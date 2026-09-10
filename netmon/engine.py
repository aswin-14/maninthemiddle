"""
Capture engine: device discovery + live per-device traffic/DNS accounting.

Runs a scapy AsyncSniffer in a background thread and keeps a thread-safe
snapshot of everything it has seen. The GUI polls snapshot() on a timer.

Requires root (raw sockets). Use only on a network you own/administer.
"""
import ipaddress
import threading
import time
from collections import defaultdict

from scapy.all import (
    AsyncSniffer, ARP, Ether, IP, IPv6, TCP, UDP, DNS, DNSQR, srp, conf,
    get_if_addr, get_if_hwaddr,
)

from . import deepparse

try:
    from mac_vendor_lookup import MacLookup
    _MACLOOKUP = MacLookup()
except Exception:
    _MACLOOKUP = None


def vendor_for(mac):
    if not _MACLOOKUP or not mac:
        return ""
    try:
        return _MACLOOKUP.lookup(mac)
    except Exception:
        return ""


# Common port -> label, so the UI can show human-friendly service names.
PORT_LABELS = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP",
    25: "SMTP", 587: "SMTP", 993: "IMAPS", 995: "POP3S", 143: "IMAP",
    123: "NTP", 3389: "RDP", 5228: "Google", 8080: "HTTP-alt",
    1935: "RTMP", 3478: "STUN/RTC", 19302: "WebRTC",
}


class Device:
    __slots__ = ("mac", "ip", "hostname", "vendor", "first_seen", "last_seen",
                 "tx_bytes", "rx_bytes", "packets", "dns", "peers",
                 "sites", "http", "open_ports", "_tx_hist", "_rx_hist")

    def __init__(self, mac, ip=""):
        now = time.time()
        self.mac = mac
        self.ip = ip
        self.hostname = ""
        self.vendor = vendor_for(mac)
        self.first_seen = now
        self.last_seen = now
        self.tx_bytes = 0          # bytes sent by this device (upload)
        self.rx_bytes = 0          # bytes received by this device (download)
        self.packets = 0
        self.dns = []              # list of (ts, qname)
        self.peers = defaultdict(int)   # (remote_ip, port, proto) -> bytes
        self.sites = defaultdict(int)   # hostname (TLS SNI / HTTP Host) -> hits
        self.http = []             # list of dicts: plaintext HTTP requests
        self.open_ports = {}       # port -> service (from nmap scan)
        self._tx_hist = []         # (ts, tx_bytes) samples for rate calc
        self._rx_hist = []

    def rate(self):
        """Return (up_Bps, down_Bps) over ~last 3s from history samples."""
        now = time.time()
        def calc(hist, cur):
            hist.append((now, cur))
            while hist and now - hist[0][0] > 3.0:
                hist.pop(0)
            if len(hist) < 2:
                return 0.0
            dt = hist[-1][0] - hist[0][0]
            db = hist[-1][1] - hist[0][1]
            return db / dt if dt > 0 else 0.0
        return calc(self._tx_hist, self.tx_bytes), calc(self._rx_hist, self.rx_bytes)


class Engine:
    def __init__(self, iface):
        self.iface = iface
        self.lock = threading.Lock()
        self.devices = {}          # mac -> Device
        self._ip_index = {}        # ip  -> Device (for MITM rx attribution)
        self._dns_names = {}       # resolved ip -> hostname (reverse of DNS answers)
        self.sniffer = None
        self.running = False
        self.local_ip = get_if_addr(iface)
        try:
            self.own_mac = get_if_hwaddr(iface).lower()
        except Exception:
            self.own_mac = ""
        try:
            self.net = ipaddress.ip_network(self.local_ip + "/24", strict=False)
        except Exception:
            self.net = None
        self.pkt_count = 0
        self.started_at = None
        self.alerts = []           # global security findings (cleartext creds, etc.)
        self._alert_keys = set()   # dedupe alerts

    # ---- discovery -------------------------------------------------------
    def arp_scan(self, timeout=2):
        """Active ARP sweep of the /24 to enumerate live devices."""
        if not self.net:
            return
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(self.net)),
            timeout=timeout, iface=self.iface, verbose=0,
        )
        with self.lock:
            for _, r in ans:
                self._touch(r.hwsrc, r.psrc)

    # ---- sniff loop ------------------------------------------------------
    def start(self):
        self.started_at = time.time()
        self.running = True
        self.sniffer = AsyncSniffer(iface=self.iface, prn=self._on_pkt, store=False)
        self.sniffer.start()

    def stop(self):
        self.running = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass

    def _touch(self, mac, ip=""):
        if not mac:
            return None
        mac = mac.lower()
        d = self.devices.get(mac)
        if d is None:
            d = Device(mac, ip)
            self.devices[mac] = d
        if ip and not d.ip:
            d.ip = ip
        if d.ip:
            self._ip_index[d.ip] = d
        d.last_seen = time.time()
        return d

    def _dev_for_ip(self, ip):
        return self._ip_index.get(ip)

    def _add_alert(self, ip, kind, detail, severity):
        """Record a security finding, de-duplicated on (ip, kind, detail)."""
        key = (ip, kind, detail)
        if key in self._alert_keys:
            return
        self._alert_keys.add(key)
        self.alerts.append({"ts": time.time(), "ip": ip or "?",
                            "kind": kind, "detail": detail, "severity": severity})
        if len(self.alerts) > 500:
            self.alerts = self.alerts[-500:]

    def port_scan(self, ip):
        """Active TCP port scan via nmap; fills the device's open_ports. Blocking."""
        import re
        import subprocess
        try:
            out = subprocess.run(
                ["nmap", "-Pn", "-T4", "--top-ports", "200", ip],
                capture_output=True, text=True, timeout=120).stdout
        except Exception as e:
            return {"error": str(e)}
        found = {}
        for line in out.splitlines():
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
            if m:
                found[int(m.group(1))] = m.group(2)
        with self.lock:
            d = self._dev_for_ip(ip)
            if d is not None:
                d.open_ports.update(found)
        return found

    def _is_local(self, ip):
        if not ip or not self.net:
            return False
        try:
            return ipaddress.ip_address(ip) in self.net
        except Exception:
            return False

    def _on_pkt(self, pkt):
        self.pkt_count += 1
        try:
            self._process(pkt)
        except Exception:
            pass

    def _process(self, pkt):
        with self.lock:
            # ARP announces device presence
            if ARP in pkt:
                a = pkt[ARP]
                if a.hwsrc and a.psrc:
                    self._touch(a.hwsrc, a.psrc)
                return

            if Ether not in pkt:
                return
            eth = pkt[Ether]
            size = len(pkt)

            ipsrc = ipdst = None
            if IP in pkt:
                ipsrc, ipdst = pkt[IP].src, pkt[IP].dst
            elif IPv6 in pkt:
                ipsrc, ipdst = pkt[IPv6].src, pkt[IPv6].dst

            src_local = self._is_local(ipsrc)
            dst_local = self._is_local(ipdst)

            dev = None
            if src_local:
                # eth.src is the true owner of an outgoing packet (even under MITM)
                dev = self._touch(eth.src, ipsrc)
                if dev:
                    dev.tx_bytes += size
                    dev.packets += 1
            if dst_local:
                # under MITM eth.dst is OUR mac, so attribute by destination IP
                dev2 = self._dev_for_ip(ipdst)
                if dev2 is None and eth.dst != self.own_mac:
                    dev2 = self._touch(eth.dst, ipdst)
                if dev2:
                    dev2.rx_bytes += size
                    dev2.packets += 1

            # peer/service accounting (from the local device's perspective)
            port = None
            proto = ""
            if TCP in pkt:
                proto = "TCP"
                port = pkt[TCP].dport if src_local else pkt[TCP].sport
            elif UDP in pkt:
                proto = "UDP"
                port = pkt[UDP].dport if src_local else pkt[UDP].sport
            if dev is not None and ipdst and not dst_local and port:
                dev.peers[(ipdst, port, proto)] += size

            # DNS: capture the queried name (the "what site" signal)
            if DNS in pkt and pkt[DNS].qd is not None and pkt[DNS].qr == 0:
                try:
                    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                except Exception:
                    qname = ""
                if qname and src_local and dev is not None:
                    dev.dns.append((time.time(), qname))
                    if len(dev.dns) > 500:
                        dev.dns = dev.dns[-500:]

            # ---- deep inspection of TCP payloads ----
            if TCP in pkt:
                tcp = pkt[TCP]
                flags = str(tcp.flags)
                # a local device answering SYN-ACK is listening on that port
                if src_local and dev is not None and "S" in flags and "A" in flags:
                    dev.open_ports.setdefault(int(tcp.sport), "listening")

                try:
                    raw = bytes(tcp.payload)
                except Exception:
                    raw = b""
                if raw:
                    flow_dev = dev if src_local else self._dev_for_ip(ipdst)
                    dev_ip = ipsrc if src_local else ipdst
                    to_server = src_local

                    # TLS SNI -> the actual website inside HTTPS
                    sni = deepparse.parse_tls_sni(raw)
                    if sni and flow_dev is not None:
                        flow_dev.sites[sni] += 1

                    # plaintext HTTP request -> full URL, and creds if present
                    if to_server:
                        h = deepparse.parse_http_request(raw)
                        if h and flow_dev is not None:
                            if h["host"]:
                                flow_dev.sites[h["host"]] += 1
                            flow_dev.http.append((time.time(), h))
                            if len(flow_dev.http) > 300:
                                flow_dev.http = flow_dev.http[-300:]
                            if h["cred"]:
                                self._add_alert(dev_ip, "HTTP",
                                    f"cleartext credentials POSTed to {h['url']}", "critical")
                            elif h["auth"]:
                                self._add_alert(dev_ip, "HTTP",
                                    f"HTTP Basic auth (base64, not encrypted) to {h['url']}", "warn")
                            else:
                                self._add_alert(dev_ip, "HTTP",
                                    f"unencrypted HTTP: {h['method']} {h['url']}", "info")

                    # cleartext protocol detection (FTP/Telnet/mail)
                    hit = deepparse.classify_plaintext(int(port or 0), raw, to_server)
                    if hit:
                        self._add_alert(dev_ip, hit[0], hit[1], hit[2])

    # ---- snapshot for the GUI -------------------------------------------
    def snapshot(self):
        with self.lock:
            out = []
            now = time.time()
            for d in self.devices.values():
                up, down = d.rate()
                top_domains = [n for _, n in d.dns[-25:]][::-1]
                # dedupe preserving order
                seen = set(); domains = []
                for n in top_domains:
                    if n not in seen:
                        seen.add(n); domains.append(n)
                peers = sorted(d.peers.items(), key=lambda kv: -kv[1])[:8]
                sites = sorted(d.sites.items(), key=lambda kv: -kv[1])[:20]
                http = [{"ts": ts, "method": h["method"], "url": h["url"],
                         "ua": h["ua"]} for ts, h in d.http[-30:]][::-1]
                out.append({
                    "mac": d.mac, "ip": d.ip, "hostname": d.hostname,
                    "vendor": d.vendor, "online": (now - d.last_seen) < 60,
                    "last_seen": d.last_seen, "first_seen": d.first_seen,
                    "tx": d.tx_bytes, "rx": d.rx_bytes, "packets": d.packets,
                    "up": up, "down": down,
                    "domains": domains[:12],
                    "dns_count": len(d.dns),
                    "sites": [{"host": h, "hits": c} for h, c in sites],
                    "http": http,
                    "open_ports": [{"port": p, "service": s}
                                   for p, s in sorted(d.open_ports.items())],
                    "peers": [
                        {"ip": ip, "port": port, "proto": proto,
                         "label": PORT_LABELS.get(port, str(port)), "bytes": b}
                        for (ip, port, proto), b in peers
                    ],
                })
            out.sort(key=lambda x: (not x["online"], -(x["up"] + x["down"])))
            meta = {
                "iface": self.iface, "local_ip": self.local_ip,
                "net": str(self.net) if self.net else "?",
                "pkts": self.pkt_count,
                "uptime": int(now - self.started_at) if self.started_at else 0,
                "devices": len(self.devices),
                "alerts": list(self.alerts[-60:])[::-1],
            }
            return out, meta
