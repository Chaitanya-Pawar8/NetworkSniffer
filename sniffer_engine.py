"""
sniffer_engine.py
------------------
Wraps Scapy's AsyncSniffer so the GUI never freezes while packets are being
captured, and so Start/Stop actually behave predictably (the older approach
based on a plain sniff() + stop_filter only checked the stop condition when
a new packet arrived, which meant "Stop" silently did nothing if traffic
was quiet, and gave no feedback at all if capture failed to start).

AsyncSniffer gives us a real .start() / .stop() lifecycle, and a watchdog
thread reports back to the GUI immediately if the capture thread dies
(e.g. missing admin/root privileges, no capture driver installed, or an
invalid interface) instead of just capturing nothing with no explanation.
"""

import queue
import threading
import time

from scapy.all import AsyncSniffer, get_if_list, wrpcap

from packet_utils import parse_packet

PERMISSION_HINT = (
    "Capture stopped immediately after starting — no packets were seen. "
    "This almost always means one of the following:\n"
    "  1) The program is not running with Administrator (Windows) or root/sudo "
    "(macOS/Linux) privileges.\n"
    "  2) No packet capture driver is installed — install 'Npcap' on Windows "
    "(in WinPcap-compatible mode) or make sure libpcap is installed on Linux/macOS.\n"
    "  3) The selected network interface is wrong or inactive — try 'Any (all interfaces)'.\n"
    "  4) A firewall, VPN, or sandboxed/virtual environment is blocking raw sockets.\n"
    "See the README's Troubleshooting section for step-by-step fixes."
)


class SnifferEngine:
    def __init__(self):
        self.packet_queue: "queue.Queue" = queue.Queue()
        self.captured_packets = []
        self._sniffer: AsyncSniffer | None = None
        self._manual_stop = False

    # ---------------------------------------------------------- interfaces
    @staticmethod
    def list_interfaces():
        try:
            return get_if_list()
        except Exception:
            return []

    # ------------------------------------------------------------- control
    def start(self, iface: str | None, bpf_filter: str | None):
        if self.is_running():
            return

        self.captured_packets = []
        self._manual_stop = False

        kwargs = {"prn": self._on_packet, "store": False}
        if iface:
            kwargs["iface"] = iface
        if bpf_filter:
            kwargs["filter"] = bpf_filter

        self._sniffer = AsyncSniffer(**kwargs)

        try:
            self._sniffer.start()
        except Exception as exc:
            self.packet_queue.put({"error": f"Could not start capture: {exc}"})
            self._sniffer = None
            return

        # Give the capture thread a beat to fail (permission errors, bad
        # interface, missing driver) and surface that clearly in the GUI
        # instead of silently showing an empty, still-"running" table.
        threading.Thread(target=self._watchdog, daemon=True).start()

    def _watchdog(self):
        time.sleep(1.5)
        if (
            not self._manual_stop
            and self._sniffer is not None
            and not self._sniffer.running
            and not self.captured_packets
        ):
            self.packet_queue.put({"error": PERMISSION_HINT})

    def stop(self):
        self._manual_stop = True
        if self._sniffer is not None:
            try:
                if self._sniffer.running:
                    self._sniffer.stop()
            except Exception:
                pass

    def is_running(self) -> bool:
        return self._sniffer is not None and self._sniffer.running

    # --------------------------------------------------------- packet flow
    def _on_packet(self, pkt):
        parsed = parse_packet(pkt)
        self.captured_packets.append(pkt)
        self.packet_queue.put(parsed)

    # ------------------------------------------------------------- export
    def export_pcap(self, filepath: str):
        if not self.captured_packets:
            raise ValueError("No packets captured yet — nothing to export.")
        wrpcap(filepath, self.captured_packets)
