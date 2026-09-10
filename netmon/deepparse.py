"""
Deep packet parsing helpers — pure functions over raw TCP payloads.

Kept separate from the engine so they can be unit-tested without live capture.
Everything is best-effort and must never raise on malformed input.
"""

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ",
                b"OPTIONS ", b"PATCH ", b"CONNECT ")


def parse_tls_sni(data: bytes):
    """
    Extract the SNI hostname from a TLS ClientHello. Returns str or None.
    Walks the record -> handshake -> extensions -> server_name extension.
    """
    try:
        if len(data) < 45 or data[0] != 0x16:          # 0x16 = TLS handshake
            return None
        # TLS record header = 5 bytes; handshake starts after it
        if data[5] != 0x01:                            # 0x01 = ClientHello
            return None
        p = 5 + 4                                       # skip record + hs header
        p += 2                                           # client_version
        p += 32                                          # random
        if p >= len(data):
            return None
        sid_len = data[p]; p += 1 + sid_len              # session id
        if p + 2 > len(data):
            return None
        cs_len = int.from_bytes(data[p:p+2], "big"); p += 2 + cs_len   # cipher suites
        if p >= len(data):
            return None
        comp_len = data[p]; p += 1 + comp_len            # compression methods
        if p + 2 > len(data):
            return None
        ext_total = int.from_bytes(data[p:p+2], "big"); p += 2
        end = min(len(data), p + ext_total)
        while p + 4 <= end:
            etype = int.from_bytes(data[p:p+2], "big")
            elen = int.from_bytes(data[p+2:p+4], "big")
            p += 4
            if etype == 0x0000:                          # server_name
                # server_name_list(2) name_type(1) name_len(2) name
                if p + 5 > len(data):
                    return None
                name_len = int.from_bytes(data[p+3:p+5], "big")
                host = data[p+5:p+5+name_len]
                try:
                    return host.decode("idna") if host else None
                except Exception:
                    return host.decode("ascii", "ignore") or None
            p += elen
    except Exception:
        return None
    return None


def parse_http_request(data: bytes):
    """
    Parse a plaintext HTTP request. Returns dict or None:
      {method, host, path, url, ua, auth, cred}
    'auth'/'cred' are set when credentials appear in the clear.
    """
    try:
        if not data.startswith(HTTP_METHODS):
            return None
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        method, path, _ = (lines[0].decode("ascii", "ignore").split(" ") + ["", "", ""])[:3]
        host = ua = auth = ""
        for ln in lines[1:]:
            low = ln.lower()
            if low.startswith(b"host:"):
                host = ln[5:].strip().decode("ascii", "ignore")
            elif low.startswith(b"user-agent:"):
                ua = ln[11:].strip().decode("ascii", "ignore")
            elif low.startswith(b"authorization:"):
                auth = ln[14:].strip().decode("ascii", "ignore")
        cred = ""
        btxt = body.decode("ascii", "ignore").lower()
        for key in ("password=", "passwd=", "pass=", "pwd=", "user=", "username=", "email="):
            if key in btxt:
                cred = body.decode("ascii", "ignore")[:200]
                break
        url = f"http://{host}{path}" if host else path
        return {"method": method, "host": host, "path": path, "url": url,
                "ua": ua, "auth": auth, "cred": cred}
    except Exception:
        return None


def classify_plaintext(port, data, to_server):
    """
    Detect notable cleartext protocol activity on well-known ports.
    Returns (kind, detail, severity) or None.  severity: info|warn|critical
    """
    try:
        txt = data.decode("ascii", "ignore").strip()
        if not txt:
            return None
        if port == 21:                                   # FTP control
            if to_server and txt.upper().startswith("USER "):
                return ("FTP", f"cleartext login user: {txt[5:][:60]}", "critical")
            if to_server and txt.upper().startswith("PASS "):
                return ("FTP", "cleartext FTP password sent", "critical")
            return ("FTP", f"cleartext FTP: {txt[:60]}", "warn")
        if port == 23:                                   # Telnet
            snippet = "".join(c for c in txt if 32 <= ord(c) < 127)[:60]
            return ("Telnet", f"unencrypted telnet data: {snippet!r}", "critical")
        if port in (110, 143) and to_server and txt.upper().startswith(("USER ", "LOGIN ", "A LOGIN")):
            return ("Mail", f"cleartext mail login: {txt[:60]}", "warn")
        if port == 25 and to_server and "AUTH LOGIN" in txt.upper():
            return ("SMTP", "cleartext SMTP AUTH LOGIN", "warn")
    except Exception:
        return None
    return None
