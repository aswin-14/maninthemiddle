# netmon — home network monitor (GUI)

A desktop dashboard that shows every device on **a network you own or
administer**, their live upload/download, the domains each device looks up,
and which servers they connect to.

## Run

```bash
cd /home/ubuntu/net-monitor
sudo ./.venv/bin/python run.py          # auto-picks / prompts for interface
# or force an interface:
sudo ./.venv/bin/python run.py 
then select the wifi-interface
```

Root is required — raw packet capture needs it. Without root the UI still
opens but shows a warning and no live traffic.

## What it shows

- **Device list** — IP, MAC, manufacturer, hostname, online/offline, live
  up/down rate, total bytes, last seen. Click a device for detail.
- **Domains (DNS)** — the sites each device asks for. This is the honest
  "what are they browsing" signal.
- **Connections** — top remote IPs + service (HTTPS, DNS, RTC, …) per device.
- **Export CSV** of the whole inventory.

## What it CANNOT show (by design / by physics)

- **Actual search terms, messages, page content, passwords.** Modern traffic
  is HTTPS/TLS-encrypted — you see *that* a device contacted a site, not what
  was typed or read. Decrypting it would need a forged certificate installed
  on each device (only possible on hardware you control) and is defeated by
  app certificate pinning.

## Seeing OTHER devices' traffic

On Wi-Fi you normally only see this machine's own packets + broadcasts.
For full-network visibility, run netmon on one of:
- your **router/gateway**, or
- a box set as the network's **DNS server** (Pi-hole style — gives you every
  device's domain lookups cleanly).

Device discovery (ARP) works from any host on the LAN regardless.

## Ethics / legality

Intended for your own home/lab network, or one you're authorized to
administer. Monitoring a network or people without authorization is illegal
in most places. Don't.

## Full-network visibility: Intercept (ARP MITM)

By default your laptop only sees its own traffic. To pull a **specific
device's** full traffic through this machine:

1. Select one or more devices in the table (Ctrl/Shift-click for several).
2. Click **Intercept selected** and confirm.

netmon then ARP-spoofs those devices ↔ the gateway so their packets route
through this host. It automatically:
- enables kernel **IP forwarding** (`net.ipv4.ip_forward`) so the devices stay
  online while intercepted,
- **restores** the real ARP mappings and the previous ip_forward value when you
  click **Stop intercept** or close the app.

This is an active man-in-the-middle technique. It is legitimate on a network you
own or are explicitly authorized to test, and disruptive/illegal otherwise. It
still does **not** decrypt HTTPS — you get more volume of the same
domain/metadata visibility, not page content.

## Deep inspection (per device)

Selecting a device shows four tabs plus a global alerts panel:

- **Websites** — the real hostnames contacted, pulled from the **TLS SNI** field
  in each HTTPS handshake (e.g. `www.instagram.com`) plus HTTP `Host` headers,
  with DNS lookups underneath as a fallback. This is the most precise "what site"
  signal available without breaking encryption.
- **HTTP (plaintext)** — full URLs, method and User-Agent for any **unencrypted**
  HTTP the device sends. Most sites are HTTPS, so this is usually sparse — which
  is the point: anything here is genuinely in the clear.
- **Open ports** — services listening on the device. Passively learned when other
  hosts connect to it, or actively via the **Scan ports** button (nmap top-200).
- **Connections** — top remote IP : service by volume.

### Security alerts panel

Flags cleartext exposure across all devices, newest first:
- 🔴 **critical** — credentials sent in the clear: HTTP login POSTs, FTP
  `USER`/`PASS`, Telnet sessions.
- 🟠 **warn** — HTTP Basic auth (base64 ≠ encryption), cleartext mail/SMTP auth.
- 🔵 **info** — plain HTTP browsing (unencrypted but no creds).

Still bounded by the same rule: SNI/Host tells you the **site**, never the
encrypted page content or search terms.
