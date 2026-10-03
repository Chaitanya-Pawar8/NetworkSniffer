"""
gui_app.py
----------
A dark, gold-accented desktop GUI for the Network Sniffer,
built with plain Tkinter/ttk so it runs with zero extra GUI dependencies
beyond Scapy itself.
"""

import os
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from sniffer_engine import SnifferEngine
from packet_utils import hex_dump, get_payload_bytes

# ---------------------------------------------------------------- palette
GOLD = "#d4af37"
GOLD_DIM = "#8a742a"
ONYX = "#0b0b0d"
CHARCOAL = "#161617"
PANEL = "#1c1c1f"
IVORY = "#f2ede1"
MUTED = "#8f8b82"
ACCENT_RED = "#c94f4f"
ACCENT_GREEN = "#4fc98b"
ANY_IFACE_LABEL = "Any (all interfaces)"

PROTOCOL_COLORS = {
    "TCP": "#e3c567",
    "UDP": "#7fb3d5",
    "ICMP": "#e07a5f",
    "ARP": "#a389d4",
    "ETHER": MUTED,
}


class NetworkSnifferApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.engine = SnifferEngine()
        self.packet_count = 0
        self.start_time = None
        self.selected_row_data = {}
        self.row_lookup = {}

        self._configure_root()
        self._build_style()
        self._build_layout()
        self._poll_queue()

    # ---------------------------------------------------------------- root
    def _configure_root(self):
        self.root.title("Network Sniffer")
        self.root.geometry("1180x720")
        self.root.minsize(980, 600)
        self.root.configure(bg=ONYX)

    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("TFrame", background=ONYX)
        style.configure("Panel.TFrame", background=PANEL)

        style.configure(
            "TLabel", background=ONYX, foreground=IVORY, font=("Georgia", 10)
        )
        style.configure(
            "Header.TLabel",
            background=ONYX,
            foreground=GOLD,
            font=("Georgia", 20, "bold"),
        )
        style.configure(
            "SubHeader.TLabel",
            background=ONYX,
            foreground=MUTED,
            font=("Georgia", 10, "italic"),
        )
        style.configure(
            "Stat.TLabel",
            background=PANEL,
            foreground=GOLD,
            font=("Consolas", 11, "bold"),
        )
        style.configure(
            "StatCaption.TLabel",
            background=PANEL,
            foreground=MUTED,
            font=("Georgia", 8),
        )

        style.configure(
            "Gold.TButton",
            background=GOLD,
            foreground=ONYX,
            font=("Georgia", 10, "bold"),
            padding=8,
            borderwidth=0,
        )
        style.map("Gold.TButton", background=[("active", GOLD_DIM)])

        style.configure(
            "Ghost.TButton",
            background=CHARCOAL,
            foreground=IVORY,
            font=("Georgia", 10),
            padding=8,
            borderwidth=1,
        )
        style.map("Ghost.TButton", background=[("active", PANEL)])

        style.configure(
            "TEntry",
            fieldbackground=CHARCOAL,
            foreground=IVORY,
            insertcolor=GOLD,
            bordercolor=GOLD_DIM,
            padding=6,
        )
        style.configure(
            "TCombobox",
            fieldbackground=CHARCOAL,
            background=CHARCOAL,
            foreground=IVORY,
            arrowcolor=GOLD,
            padding=6,
        )

        style.configure(
            "Sniffer.Treeview",
            background=CHARCOAL,
            fieldbackground=CHARCOAL,
            foreground=IVORY,
            rowheight=26,
            borderwidth=0,
            font=("Consolas", 10),
        )
        style.configure(
            "Sniffer.Treeview.Heading",
            background=PANEL,
            foreground=GOLD,
            font=("Georgia", 10, "bold"),
            borderwidth=0,
        )
        style.map("Sniffer.Treeview", background=[("selected", GOLD_DIM)],
                  foreground=[("selected", ONYX)])

    # -------------------------------------------------------------- layout
    def _build_layout(self):
        self._build_header()
        self._build_control_bar()
        self._build_body()
        self._build_status_bar()

    def _build_header(self):
        header = ttk.Frame(self.root, style="TFrame")
        header.pack(fill="x", padx=24, pady=(20, 8))

        ttk.Label(header, text="⟡  NETWORK SNIFFER", style="Header.TLabel").pack(
            side="left"
        )
        ttk.Label(
            header,
            text="   For legal purposes only",
            style="SubHeader.TLabel",
        ).pack(side="left", padx=(12, 0), pady=(8, 0))

        divider = tk.Frame(self.root, bg=GOLD_DIM, height=1)
        divider.pack(fill="x", padx=24, pady=(0, 12))

    def _build_control_bar(self):
        bar = ttk.Frame(self.root, style="TFrame")
        bar.pack(fill="x", padx=24, pady=(0, 12))

        # Interface selector
        ttk.Label(bar, text="Interface").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.iface_var = tk.StringVar()
        detected = self.engine.list_interfaces()
        interfaces = [ANY_IFACE_LABEL] + detected
        self.iface_combo = ttk.Combobox(
            bar, textvariable=self.iface_var, values=interfaces, width=26, state="readonly"
        )
        self.iface_combo.current(0)
        self.iface_combo.grid(row=0, column=1, padx=(0, 18))

        # BPF filter
        ttk.Label(bar, text="Filter (BPF)").grid(row=0, column=2, sticky="w", padx=(0, 6))
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(bar, textvariable=self.filter_var, width=28)
        filter_entry.grid(row=0, column=3, padx=(0, 6))
        filter_entry.insert(0, "e.g. tcp port 80")
        filter_entry.bind("<FocusIn>", lambda e: self._clear_placeholder(filter_entry))

        # Buttons
        self.start_btn = ttk.Button(
            bar, text="▶  Start Capture", style="Gold.TButton", command=self.start_capture
        )
        self.start_btn.grid(row=0, column=4, padx=(18, 6))

        self.stop_btn = ttk.Button(
            bar, text="■  Stop", style="Ghost.TButton", command=self.stop_capture, state="disabled"
        )
        self.stop_btn.grid(row=0, column=5, padx=6)

        ttk.Button(
            bar, text="Clear", style="Ghost.TButton", command=self.clear_capture
        ).grid(row=0, column=6, padx=6)

        ttk.Button(
            bar, text="Export .pcap", style="Ghost.TButton", command=self.export_pcap
        ).grid(row=0, column=7, padx=6)

        ttk.Button(
            bar, text="Save Log (.txt)", style="Ghost.TButton", command=self.save_log
        ).grid(row=0, column=8, padx=6)

    @staticmethod
    def _clear_placeholder(entry: ttk.Entry):
        if entry.get().startswith("e.g."):
            entry.delete(0, "end")

    def _build_body(self):
        body = ttk.Frame(self.root, style="TFrame")
        body.pack(fill="both", expand=True, padx=24, pady=(0, 12))
        body.rowconfigure(0, weight=3)
        body.rowconfigure(1, weight=2)
        body.columnconfigure(0, weight=1)

        # ---- Packet table
        table_frame = ttk.Frame(body, style="Panel.TFrame")
        table_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 12))

        columns = ("time", "src", "sport", "dst", "dport", "protocol", "length", "info")
        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", style="Sniffer.Treeview"
        )
        headings = {
            "time": "Time",
            "src": "Source IP",
            "sport": "Src Port",
            "dst": "Destination IP",
            "dport": "Dst Port",
            "protocol": "Protocol",
            "length": "Length",
            "info": "Summary",
        }
        widths = {
            "time": 100, "src": 150, "sport": 110, "dst": 150,
            "dport": 110, "protocol": 90, "length": 70, "info": 320,
        }
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(2, 0), pady=2)
        vsb.pack(side="right", fill="y")

        for proto, color in PROTOCOL_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)

        self.tree.bind("<<TreeviewSelect>>", self.on_row_select)

        # ---- Detail pane (hex dump + raw summary)
        detail_frame = ttk.Frame(body, style="Panel.TFrame")
        detail_frame.grid(row=1, column=0, sticky="nsew")

        ttk.Label(
            detail_frame,
            text="PACKET DETAIL",
            background=PANEL,
            foreground=GOLD,
            font=("Georgia", 10, "bold"),
        ).pack(anchor="w", padx=12, pady=(8, 0))

        self.detail_text = tk.Text(
            detail_frame,
            bg=CHARCOAL,
            fg=IVORY,
            insertbackground=GOLD,
            font=("Consolas", 9),
            relief="flat",
            wrap="none",
            height=12,
        )
        self.detail_text.pack(fill="both", expand=True, padx=12, pady=10)
        self.detail_text.insert("1.0", "Select a packet above to inspect its raw payload…")
        self.detail_text.configure(state="disabled")

    def _build_status_bar(self):
        status = ttk.Frame(self.root, style="Panel.TFrame")
        status.pack(fill="x", side="bottom")

        self.status_dot = tk.Canvas(status, width=14, height=14, bg=PANEL, highlightthickness=0)
        self.status_dot.pack(side="left", padx=(16, 6), pady=8)
        self._dot_id = self.status_dot.create_oval(2, 2, 12, 12, fill=ACCENT_RED, outline="")

        self.status_label = ttk.Label(
            status, text="Idle — ready to capture", style="StatCaption.TLabel"
        )
        self.status_label.pack(side="left", pady=8)

        self.count_label = ttk.Label(
            status, text="Packets: 0   |   Elapsed: 00:00", style="StatCaption.TLabel"
        )
        self.count_label.pack(side="right", padx=16, pady=8)

    # ---------------------------------------------------------------- ops
    def start_capture(self):
        selected = self.iface_var.get()
        iface = None if selected == ANY_IFACE_LABEL else selected
        bpf = self.filter_var.get().strip()
        if bpf.startswith("e.g."):
            bpf = ""

        try:
            self.engine.start(iface, bpf)
        except Exception as exc:
            messagebox.showerror("Capture error", str(exc))
            return

        self.start_time = time.time()
        self.packet_count = 0
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_dot.itemconfig(self._dot_id, fill=ACCENT_GREEN)
        self.status_label.configure(text=f"Capturing on '{selected}' …")

    def stop_capture(self):
        self.engine.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_dot.itemconfig(self._dot_id, fill=ACCENT_RED)
        self.status_label.configure(text="Stopped — capture idle")

    def clear_capture(self):
        self.tree.delete(*self.tree.get_children())
        self.row_lookup.clear()
        self.packet_count = 0
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", "Select a packet above to inspect its raw payload…")
        self.detail_text.configure(state="disabled")
        self.count_label.configure(text="Packets: 0   |   Elapsed: 00:00")

    def export_pcap(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")]
        )
        if not filepath:
            return
        try:
            self.engine.export_pcap(filepath)
            messagebox.showinfo("Export complete", f"Saved capture to:\n{filepath}")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    def save_log(self):
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text log", "*.txt")]
        )
        if not filepath:
            return

        rows = []
        for item_id in self.tree.get_children():
            values = self.tree.item(item_id, "values")
            rows.append(" | ".join(str(v) for v in values))

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write("Network Sniffer — Capture Log\n")
            fh.write("=" * 60 + "\n")
            fh.write("\n".join(rows))

        messagebox.showinfo("Log saved", f"Saved {len(rows)} packet rows to:\n{filepath}")

    def on_row_select(self, _event):
        selected = self.tree.selection()
        if not selected:
            return
        item_id = selected[0]
        parsed = self.row_lookup.get(item_id)
        if not parsed:
            return

        pkt = parsed["raw"]
        payload = get_payload_bytes(pkt)

        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("end", f"Summary : {parsed['summary']}\n")
        self.detail_text.insert("end", f"Length  : {parsed['length']} bytes\n")
        self.detail_text.insert("end", "-" * 70 + "\n")
        self.detail_text.insert("end", hex_dump(payload))
        self.detail_text.configure(state="disabled")

    # -------------------------------------------------------------- queue
    def _poll_queue(self):
        try:
            while True:
                item = self.engine.packet_queue.get_nowait()
                if "error" in item:
                    self.stop_capture()
                    messagebox.showwarning("No packets captured", item["error"])
                    continue
                self._insert_row(item)
        except Exception:
            pass  # queue empty, nothing to do this tick

        if self.start_time and self.engine.is_running():
            elapsed = int(time.time() - self.start_time)
            mins, secs = divmod(elapsed, 60)
            self.count_label.configure(
                text=f"Packets: {self.packet_count}   |   Elapsed: {mins:02d}:{secs:02d}"
            )

        self.root.after(150, self._poll_queue)

    def _insert_row(self, parsed):
        self.packet_count += 1
        tag = parsed["protocol"] if parsed["protocol"] in PROTOCOL_COLORS else ""
        item_id = self.tree.insert(
            "",
            "end",
            values=(
                parsed["time"],
                parsed["src"],
                parsed["sport"],
                parsed["dst"],
                parsed["dport"],
                parsed["protocol"],
                parsed["length"],
                parsed["summary"],
            ),
            tags=(tag,),
        )
        self.row_lookup[item_id] = parsed
        self.tree.see(item_id)


def launch():
    root = tk.Tk()
    app = NetworkSnifferApp(root)
    root.mainloop()
