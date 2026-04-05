"""
PRODIGY_CS_05 - Network Packet Analyzer
Prodigy Infotech Cybersecurity Internship - Task 05
Captures and analyzes network packets displaying source/dest IPs, protocols, and payload.
⚠️  FOR EDUCATIONAL PURPOSES ONLY — Run with admin/root privileges.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import struct
import textwrap
from datetime import datetime


def parse_ethernet(data):
    dest, src, proto = struct.unpack('! 6s 6s H', data[:14])
    return {
        'dest_mac': ':'.join(f'{b:02x}' for b in dest),
        'src_mac':  ':'.join(f'{b:02x}' for b in src),
        'proto':    socket.htons(proto),
        'payload':  data[14:]
    }


def parse_ipv4(data):
    version_ihl = data[0]
    ihl = (version_ihl & 0xF) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return {
        'version': version_ihl >> 4,
        'ihl':     ihl,
        'ttl':     ttl,
        'proto':   proto,
        'src':     socket.inet_ntoa(src),
        'dst':     socket.inet_ntoa(target),
        'payload': data[ihl:]
    }


def parse_tcp(data):
    src_port, dst_port, seq, ack, offset_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_flags >> 12) * 4
    flags = {
        'URG': bool(offset_flags & 32),
        'ACK': bool(offset_flags & 16),
        'PSH': bool(offset_flags & 8),
        'RST': bool(offset_flags & 4),
        'SYN': bool(offset_flags & 2),
        'FIN': bool(offset_flags & 1),
    }
    return {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq':      seq,
        'ack':      ack,
        'flags':    flags,
        'payload':  data[offset:]
    }


def parse_udp(data):
    src_port, dst_port, length = struct.unpack('! H H 2x H', data[:8])
    return {'src_port': src_port, 'dst_port': dst_port, 'length': length, 'payload': data[8:]}


def parse_icmp(data):
    type_, code, checksum = struct.unpack('! B B H', data[:4])
    return {'type': type_, 'code': code, 'checksum': checksum, 'payload': data[4:]}


PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Well-known ports
PORT_MAP = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP",
    53: "DNS", 110: "POP3", 143: "IMAP", 3306: "MySQL", 5432: "PostgreSQL",
    3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer - PRODIGY_CS_05")
        self.root.geometry("980x700")
        self.root.configure(bg="#0a0d14")
        self.root.resizable(True, True)

        self.running = False
        self.thread = None
        self.packet_count = 0
        self.packets = []

        self.build_ui()

    def build_ui(self):
        # Header
        hdr = tk.Frame(self.root, bg="#0a0d14")
        hdr.pack(fill='x', padx=20, pady=(16, 0))
        tk.Label(hdr, text="📡  Network Packet Analyzer",
                 font=("Courier New", 18, "bold"), fg="#00aaff", bg="#0a0d14").pack(side='left')
        tk.Label(hdr, text="PRODIGY_CS_05",
                 font=("Courier New", 8), fg="#223344", bg="#0a0d14").pack(side='right', pady=8)

        # Warning
        warn = tk.Frame(self.root, bg="#0a1520",
                        highlightthickness=1, highlightbackground="#113355")
        warn.pack(padx=20, fill='x', pady=8)
        tk.Label(warn, text="⚠️  Requires admin/root privileges. For educational use only. Analyze only your own network traffic.",
                 font=("Courier New", 8), fg="#3399cc", bg="#0a1520", pady=5).pack()

        tk.Frame(self.root, height=1, bg="#111a26").pack(fill='x', padx=20, pady=2)

        # Controls
        ctrl = tk.Frame(self.root, bg="#0a0d14")
        ctrl.pack(padx=20, fill='x', pady=8)

        self.start_btn = self._btn(ctrl, "▶  START CAPTURE", "#00aaff", "#001a2e", self.start_capture)
        self.start_btn.pack(side='left', padx=(0, 8))

        self.stop_btn = self._btn(ctrl, "⏹  STOP", "#555577", "#111122", self.stop_capture)
        self.stop_btn.config(state='disabled')
        self.stop_btn.pack(side='left', padx=(0, 8))

        self._btn(ctrl, "🗑  CLEAR", "#334455", "#0a0d14", self.clear_all).pack(side='left')

        # Filter
        tk.Label(ctrl, text="Filter Protocol:", font=("Courier New", 9),
                 fg="#445566", bg="#0a0d14").pack(side='left', padx=(20, 4))
        self.filter_var = tk.StringVar(value="ALL")
        for opt in ["ALL", "TCP", "UDP", "ICMP"]:
            tk.Radiobutton(ctrl, text=opt, variable=self.filter_var, value=opt,
                           font=("Courier New", 8), fg="#00aaff", bg="#0a0d14",
                           selectcolor="#0a0d14", activeforeground="#00aaff",
                           activebackground="#0a0d14").pack(side='left', padx=2)

        # Status
        self.status_var = tk.StringVar(value="Ready — Click START to begin capture")
        self.pkt_count_var = tk.StringVar(value="Packets: 0")
        status_bar = tk.Frame(self.root, bg="#0a0d14")
        status_bar.pack(padx=20, fill='x')
        self.status_dot = tk.Label(status_bar, text="●", font=("Courier New", 10),
                                   fg="#333344", bg="#0a0d14")
        self.status_dot.pack(side='left')
        tk.Label(status_bar, textvariable=self.status_var, font=("Courier New", 8),
                 fg="#445566", bg="#0a0d14").pack(side='left', padx=4)
        tk.Label(status_bar, textvariable=self.pkt_count_var, font=("Courier New", 8, "bold"),
                 fg="#00aaff", bg="#0a0d14").pack(side='right')

        # Packet table
        table_frame = tk.Frame(self.root, bg="#0a0d14",
                               highlightthickness=1, highlightbackground="#111a26")
        table_frame.pack(padx=20, fill='both', expand=True, pady=8)

        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Dark.Treeview",
                        background="#0d1117", foreground="#aaccdd",
                        fieldbackground="#0d1117", font=("Courier New", 8),
                        rowheight=22)
        style.configure("Dark.Treeview.Heading",
                        background="#0a1520", foreground="#00aaff",
                        font=("Courier New", 8, "bold"), relief='flat')
        style.map("Dark.Treeview", background=[('selected', '#0f2a3e')])

        cols = ("#", "Time", "Protocol", "Source IP", "Src Port", "Dest IP", "Dst Port", "Size", "Info")
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings',
                                 style="Dark.Treeview", selectmode='browse')

        widths = [40, 80, 60, 120, 70, 120, 70, 55, 200]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, minwidth=30, anchor='w')

        vsb = ttk.Scrollbar(table_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side='left', fill='both', expand=True)
        vsb.pack(side='right', fill='y')
        self.tree.bind('<<TreeviewSelect>>', self.on_select)

        # Detail panel
        detail_frame = tk.Frame(self.root, bg="#0a0d14",
                                highlightthickness=1, highlightbackground="#111a26")
        detail_frame.pack(padx=20, fill='x', pady=(0, 12))
        tk.Label(detail_frame, text="Packet Detail & Payload",
                 font=("Courier New", 8, "bold"), fg="#334455", bg="#0a0d14").pack(anchor='w', padx=8, pady=(4, 0))
        self.detail_text = scrolledtext.ScrolledText(
            detail_frame, height=7, font=("Courier New", 8),
            bg="#080d14", fg="#5599bb", relief='flat',
            padx=8, pady=6, state='disabled', wrap='none'
        )
        self.detail_text.pack(fill='x', padx=4, pady=(0, 4))

    def _btn(self, parent, text, fg, bg, cmd):
        return tk.Button(parent, text=text, font=("Courier New", 9, "bold"),
                         fg=fg, bg=bg, activeforeground=fg, activebackground="#111122",
                         relief='flat', cursor='hand2', pady=6, padx=10,
                         highlightthickness=1, highlightbackground=fg, command=cmd)

    def start_capture(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            # On Windows, bind to the local host
            try:
                host = socket.gethostbyname(socket.gethostname())
                self.sock.bind((host, 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                try:
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                except AttributeError:
                    pass  # Linux doesn't need this
            except Exception:
                pass
        except PermissionError:
            messagebox.showerror("Permission Denied",
                "Run this program as Administrator (Windows) or with sudo (Linux/Mac).")
            return
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        self.running = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_dot.config(fg="#00aaff")
        self.status_var.set("Capturing packets...")

        self.thread = threading.Thread(target=self.capture_loop, daemon=True)
        self.thread.start()

    def capture_loop(self):
        while self.running:
            try:
                raw, _ = self.sock.recvfrom(65535)
                self.process_packet(raw)
            except Exception:
                break

    def process_packet(self, data):
        try:
            ip = parse_ipv4(data)
            proto_num = ip['proto']
            proto_name = PROTO_MAP.get(proto_num, f"PROTO-{proto_num}")

            # Apply filter
            filt = self.filter_var.get()
            if filt != "ALL" and proto_name != filt:
                return

            src_port = dst_port = "-"
            info = ""

            if proto_num == 6:  # TCP
                tcp = parse_tcp(ip['payload'])
                src_port = str(tcp['src_port'])
                dst_port = str(tcp['dst_port'])
                flags_active = [f for f, v in tcp['flags'].items() if v]
                svc = PORT_MAP.get(tcp['dst_port'], PORT_MAP.get(tcp['src_port'], ''))
                info = f"[{','.join(flags_active)}] {svc}"
                payload_preview = tcp['payload'][:80]
            elif proto_num == 17:  # UDP
                udp = parse_udp(ip['payload'])
                src_port = str(udp['src_port'])
                dst_port = str(udp['dst_port'])
                svc = PORT_MAP.get(udp['dst_port'], PORT_MAP.get(udp['src_port'], ''))
                info = f"Len={udp['length']} {svc}"
                payload_preview = udp['payload'][:80]
            elif proto_num == 1:  # ICMP
                icmp = parse_icmp(ip['payload'])
                info = f"Type={icmp['type']} Code={icmp['code']}"
                payload_preview = icmp['payload'][:80]
            else:
                payload_preview = ip['payload'][:80]

            self.packet_count += 1
            now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            size = len(data)

            row_data = (
                self.packet_count,
                now,
                proto_name,
                ip['src'],
                src_port,
                ip['dst'],
                dst_port,
                size,
                info
            )
            self.packets.append({
                'ip': ip,
                'proto': proto_name,
                'payload_preview': payload_preview,
                'row': row_data
            })

            self.root.after(0, self.insert_row, row_data, proto_name)
        except Exception:
            pass

    def insert_row(self, row_data, proto):
        colors = {"TCP": "#00aaff", "UDP": "#00ffcc", "ICMP": "#ffaa00"}
        tag = proto
        self.tree.insert("", "end", values=row_data, tags=(tag,))
        self.tree.tag_configure("TCP",  foreground="#7abbcc")
        self.tree.tag_configure("UDP",  foreground="#7accaa")
        self.tree.tag_configure("ICMP", foreground="#ccaa55")
        self.tree.yview_moveto(1)
        self.pkt_count_var.set(f"Packets: {self.packet_count}")

    def on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx >= len(self.packets):
            return
        pkt = self.packets[idx]
        ip = pkt['ip']
        payload = pkt['payload_preview']

        detail = (
            f"Protocol   : {pkt['proto']}\n"
            f"Source IP  : {ip['src']}   →   Dest IP: {ip['dst']}\n"
            f"TTL        : {ip['ttl']}   Version: {ip['version']}   IHL: {ip['ihl']}\n"
            f"Payload    : {payload.hex() if payload else '(empty)'}\n"
        )
        try:
            decoded = payload.decode('utf-8', errors='replace')
            detail += f"Decoded    : {decoded[:200]}\n"
        except Exception:
            pass

        self.detail_text.config(state='normal')
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("end", detail)
        self.detail_text.config(state='disabled')

    def stop_capture(self):
        self.running = False
        try:
            self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_dot.config(fg="#333344")
        self.status_var.set(f"Capture stopped — {self.packet_count} packets captured")

    def clear_all(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packets.clear()
        self.packet_count = 0
        self.pkt_count_var.set("Packets: 0")
        self.detail_text.config(state='normal')
        self.detail_text.delete("1.0", "end")
        self.detail_text.config(state='disabled')


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerApp(root)
    root.mainloop()
