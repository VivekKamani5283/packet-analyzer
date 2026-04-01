import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import time

from analyzer_core import PacketAnalyzer


class AnalyzerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Packet Analyzer GUI")

        # Top frame for controls
        frm = tk.Frame(root)
        frm.pack(padx=10, pady=8, fill=tk.X)

        self.pcap_path_var = tk.StringVar()
        tk.Entry(frm, textvariable=self.pcap_path_var, width=60).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(frm, text="Browse PCAP...", command=self.browse_pcap).pack(side=tk.LEFT)
        tk.Button(frm, text="Analyze PCAP", command=self.analyze_pcap).pack(side=tk.LEFT, padx=(6, 0))

        # Live capture controls
        live_frm = tk.Frame(root)
        live_frm.pack(padx=10, pady=4, fill=tk.X)
        tk.Button(live_frm, text="Start Live Capture", command=self.start_live).pack(side=tk.LEFT)
        tk.Button(live_frm, text="Stop Live Capture", command=self.stop_live).pack(side=tk.LEFT, padx=(6, 0))

        # Status banner
        self.status_var = tk.StringVar(value="Idle")
        self.status_label = tk.Label(root, textvariable=self.status_var, bg="#88cc88", fg="#003300", font=(None, 12), relief=tk.SUNKEN)
        self.status_label.pack(fill=tk.X, padx=10, pady=(6, 4))

        # Alerts area
        tk.Label(root, text="Alerts:").pack(anchor=tk.W, padx=10)
        self.alerts_box = scrolledtext.ScrolledText(root, height=8, state=tk.DISABLED)
        self.alerts_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 6))

        # Captured packets area (live / pcap contents)
        tk.Label(root, text="Captured packets:").pack(anchor=tk.W, padx=10)
        self.packets_box = scrolledtext.ScrolledText(root, height=12, state=tk.DISABLED)
        self.packets_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Analyzer instance (with callbacks)
        self.analyzer = PacketAnalyzer(alert_callback=self.on_alert, packet_callback=self.on_packet)

        self.live_thread = None
        self.live_running = threading.Event()

    def browse_pcap(self):
        path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap;*.pcapng"), ("All files", "*")])
        if path:
            self.pcap_path_var.set(path)

    def analyze_pcap(self):
        pcap = self.pcap_path_var.get()
        if not pcap or not os.path.isfile(pcap):
            messagebox.showwarning("No file", "Please choose a valid pcap file first.")
            return

        self.clear_alerts()
        self.set_status("Analyzing pcap...", good=True)

        def worker():
            try:
                self.analyzer.run_pcap(pcap)
                # If no alerts were reported, show 'You are safe'
                if not self.has_alerts():
                    self.set_status("You are safe — no alerts detected", good=True)
            except Exception as e:
                self.set_status(f"Error: {e}", good=False)

        threading.Thread(target=worker, daemon=True).start()

    def start_live(self):
        # Start AsyncSniffer-based live capture (non-blocking)
        try:
            self.clear_alerts()
            self.analyzer.start_live_async(interface=None, bpf_filter=None)
            self.set_status("Live capture running...", good=True)
        except Exception as e:
            messagebox.showerror("Live capture error", str(e))
            self.set_status(f"Live capture error: {e}", good=False)

    def stop_live(self):
        try:
            self.analyzer.stop_live_async()
            self.set_status("Live capture stopped", good=True)
        except Exception as e:
            messagebox.showerror("Stop error", str(e))
            self.set_status(f"Error stopping live capture: {e}", good=False)

    def on_alert(self, message: str):
        # Called from analyzer threads
        self.root.after(0, lambda: self._append_alert(message))

    def on_packet(self, summary: str):
        # Called from analyzer threads for every packet
        self.root.after(0, lambda: self._append_packet(summary))

    def _append_packet(self, summary: str):
        self.packets_box.configure(state=tk.NORMAL)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.packets_box.insert(tk.END, f"[{ts}] {summary}\n")
        self.packets_box.see(tk.END)
        self.packets_box.configure(state=tk.DISABLED)

    def _append_alert(self, message: str):
        self.alerts_box.configure(state=tk.NORMAL)
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.alerts_box.insert(tk.END, f"[{ts}] {message}\n")
        self.alerts_box.see(tk.END)
        self.alerts_box.configure(state=tk.DISABLED)
        self.set_status(f"ALERT: {message}", good=False)

    def clear_alerts(self):
        self.alerts_box.configure(state=tk.NORMAL)
        self.alerts_box.delete(1.0, tk.END)
        self.alerts_box.configure(state=tk.DISABLED)
        # also clear captured packets view
        try:
            self.packets_box.configure(state=tk.NORMAL)
            self.packets_box.delete(1.0, tk.END)
            self.packets_box.configure(state=tk.DISABLED)
        except Exception:
            pass

    def has_alerts(self):
        return bool(self.alerts_box.get(1.0, tk.END).strip())

    def set_status(self, text: str, good: bool):
        self.status_var.set(text)
        if good:
            self.status_label.configure(bg="#88cc88", fg="#003300")
        else:
            self.status_label.configure(bg="#ff8888", fg="#330000")


def main():
    root = tk.Tk()
    app = AnalyzerGUI(root)
    root.geometry("800x500")
    root.mainloop()


if __name__ == "__main__":
    main()
