# ⟡ Network Sniffer

A real-time network packet sniffer built in Python with **Scapy** for
capture and a hand-styled **black-and-gold desktop GUI** (Tkinter) for
visualization — built for legal purposes only.

Instead of a plain terminal script, this project ships as a small desktop
application: live packet table, protocol color-coding, a hex-dump inspector
for payloads, BPF filtering, `.pcap` export, and session logging.

---

## ✨ Features

- **Live capture** of network traffic using Scapy, running on a background
  thread so the interface never freezes.
- **Polished dark UI** — onyx/charcoal background, gold accents, serif
  headings, colour-coded protocols (TCP / UDP / ICMP / ARP).
- **Protocol breakdown** — source/destination IP, source/destination port
  (with well-known service labels like `80 (HTTP)`), protocol, and length.
- **Packet inspector** — click any row to see a full hex + ASCII dump of the
  payload, just like Wireshark's byte view.
- **BPF filters** — capture only what you need, e.g. `tcp port 443`,
  `udp`, `icmp`, `host 192.168.1.1`.
- **Interface selector** — pick any network interface detected on your
  machine.
- **Export to `.pcap`** — open your capture later in Wireshark.
- **Save session log** — export the packet table as a plain-text report.
- **Live stats bar** — packet counter, elapsed capture time, and a status
  indicator (green = capturing, red = idle).

---

## 🗂 Project Structure

All files sit in a single flat folder — no subfolders — so the project is
easy to upload directly through GitHub's web interface.

```
NetworkSniffer/
├── main.py              # Entry point — run this file
├── gui_app.py            # Dark-themed Tkinter GUI
├── sniffer_engine.py     # Scapy capture logic (threaded)
├── packet_utils.py       # Packet parsing + hex-dump helpers
├── requirements.txt      # Python dependencies
├── LICENSE
├── .gitignore
└── README.md
```

`main.py` imports directly from `gui_app.py`, which imports from
`sniffer_engine.py` and `packet_utils.py`. All four `.py` files must stay
in the same folder for the imports to work.

---

## ⚙️ Installation

```bash
git clone https://github.com/Chaitanya-Pawar8/NetworkSniffer.git
cd NetworkSniffer
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

> Tkinter ships with most standard Python installations. On some minimal
> Linux distros you may need `sudo apt install python3-tk`.

---

## ▶️ Usage

Packet capture needs elevated privileges because it opens a raw socket.

```bash
# Windows (run terminal as Administrator)
python main.py

# macOS / Linux
sudo python3 main.py
```

1. Choose a network **interface** from the dropdown.
2. (Optional) Enter a **BPF filter**, e.g. `tcp port 80`.
3. Click **▶ Start Capture** — the status dot turns green and packets begin
   streaming into the table.
4. Click any row to inspect its **raw payload** in the hex-dump panel below.
5. Click **■ Stop** to end the session.
6. Use **Export .pcap** to save the raw capture (open it in Wireshark), or
   **Save Log (.txt)** for a readable summary.

---

## 🧠 What You'll Learn

- How packets are structured across the OSI/TCP-IP layers (Ethernet → IP →
  TCP/UDP/ICMP → payload).
- How to use Scapy to sniff, filter, and dissect live traffic.
- How BPF (Berkeley Packet Filter) syntax narrows a capture to what matters.
- How to build a responsive GUI that stays smooth while I/O happens on a
  separate thread.

---

## 🛠 Troubleshooting — "It ran but captured nothing"

This is almost always one of five causes. Work through them in order:

1. **Not running with elevated privileges.**
   Raw packet capture requires admin/root.
   - Windows: right-click PowerShell/CMD → *Run as Administrator*, then run `python main.py`.
   - macOS/Linux: run `sudo python3 main.py`.
   - The app itself detects this and prints a warning in the console if you forgot.

2. **Missing capture driver (Windows only).**
   Scapy needs **Npcap** to read raw traffic on Windows. Download and install it from
   [npcap.com](https://npcap.com) and tick **"Install Npcap in WinPcap API-compatible Mode"**
   during setup, then reboot.

3. **Wrong network interface selected.**
   The interface dropdown lists every adapter the OS reports, including inactive
   virtual ones (VPN adapters, Docker bridges, loopback). If you're not sure which
   one is active, leave the selector on **"Any (all interfaces)"** — this tells
   Scapy to listen on every interface at once.

4. **No traffic was actually generated during the capture window.**
   If your filter is very specific (e.g. `tcp port 443`) and you weren't actively
   browsing/downloading anything, there may simply be nothing matching to see.
   Try clearing the filter box and browsing a website in another window while
   capturing.

5. **A firewall, VPN, container, or sandboxed VM is blocking raw sockets.**
   Corporate laptops, WSL, and some cloud/VM environments intentionally block raw
   packet capture. Test on a normal physical machine you administer if you
   suspect this.

If capture stops immediately with no packets, the app will now pop up a
message explaining which of the above is most likely, instead of silently
showing an empty table.

---

## ⚠️ Ethical Use Notice

This tool is built strictly for **legal purposes only**. Only capture
traffic on networks and devices you own or have explicit permission to
test. Unauthorized packet interception may violate local laws.

---

## 🏷 About

**Author:** Chaitanya Pawar ([@Chaitanya-Pawar8](https://github.com/Chaitanya-Pawar8))

`#cybersecurity` `#python` `#networking` `#scapy`
