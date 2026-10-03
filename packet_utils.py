"""
packet_utils.py
----------------
Helper functions that turn a raw Scapy packet into a clean, display-ready
dictionary and provide a hex-dump style breakdown of the payload.

Keeping this logic separate from the GUI and the capture engine keeps the
codebase easy to extend (e.g. add new protocol parsers) without touching
the sniffing or rendering layers.
"""

from datetime import datetime

from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Raw, Ether

# Well-known ports we like to label for readability in the "Info" column.
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MYSQL",
    3389: "RDP", 5353: "mDNS", 8080: "HTTP-ALT",
}


def _label_port(port):
    if port in COMMON_PORTS:
        return f"{port} ({COMMON_PORTS[port]})"
    return str(port)


def parse_packet(pkt):
    """
    Convert a Scapy packet into a flat dict the GUI can drop straight into
    a Treeview row, plus keep the raw packet around for the detail view.
    """
    info = {
        "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src": "-",
        "dst": "-",
        "protocol": "OTHER",
        "sport": "-",
        "dport": "-",
        "length": len(pkt),
        "summary": pkt.summary(),
        "raw": pkt,
    }

    if pkt.haslayer(ARP):
        info["protocol"] = "ARP"
        info["src"] = pkt[ARP].psrc
        info["dst"] = pkt[ARP].pdst
        return info

    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        info["src"] = layer.src
        info["dst"] = layer.dst

        if pkt.haslayer(TCP):
            info["protocol"] = "TCP"
            info["sport"] = _label_port(pkt[TCP].sport)
            info["dport"] = _label_port(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            info["protocol"] = "UDP"
            info["sport"] = _label_port(pkt[UDP].sport)
            info["dport"] = _label_port(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            info["protocol"] = "ICMP"
        else:
            info["protocol"] = f"IP-PROTO-{layer.proto if pkt.haslayer(IP) else layer.nh}"
    elif pkt.haslayer(Ether):
        info["src"] = pkt[Ether].src
        info["dst"] = pkt[Ether].dst
        info["protocol"] = "ETHER"

    return info


def hex_dump(data: bytes, width: int = 16) -> str:
    """Classic offset / hex / ASCII dump, used in the detail pane."""
    if not data:
        return "<no payload captured>"

    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_part}   {ascii_part}")
    return "\n".join(lines)


def get_payload_bytes(pkt) -> bytes:
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw].load)
    return b""
