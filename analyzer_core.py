#!/usr/bin/env python3
"""
Core packet analyzer used by the GUI (clean copy).
"""
import logging
import time
import threading
from collections import defaultdict, deque

try:
    import importlib
    _scapy_all = importlib.import_module("scapy.all")
    sniff = _scapy_all.sniff
    rdpcap = _scapy_all.rdpcap
    IP = _scapy_all.IP
    TCP = _scapy_all.TCP
    ICMP = _scapy_all.ICMP
    AsyncSniffer = getattr(_scapy_all, "AsyncSniffer", None)
except Exception:
    sniff = rdpcap = IP = TCP = ICMP = AsyncSniffer = None


class PacketAnalyzer:
    def __init__(self,
                 port_threshold=20,
                 port_window=10.0,
                 ping_threshold=100,
                 ping_window=5.0,
                 alert_log_path="alerts.log",
                 alert_callback=None,
                 packet_callback=None):
        self.port_threshold = port_threshold
        self.port_window = port_window
        self.ping_threshold = ping_threshold
        self.ping_window = ping_window
        self.alert_callback = alert_callback
        self.packet_callback = packet_callback

        # Async sniffer or fallback thread
        self._sniffer = None
        # If AsyncSniffer isn't available we fall back to a thread+sniff loop controlled
        # by this event and the thread reference stored in _sniffer.
        self._stop_event = None

        self.tcp_syns = defaultdict(deque)
        self.icmp_requests = defaultdict(deque)

        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s",
                            handlers=[logging.FileHandler(alert_log_path), logging.StreamHandler()])
        self.logger = logging.getLogger("analyzer_core")

    def _prune_old(self, dq: deque, window: float):
        cutoff = time.time() - window
        while dq and (dq[0][0] < cutoff if isinstance(dq[0], tuple) else dq[0] < cutoff):
            dq.popleft()

    def process_packet(self, pkt):
        if IP is None:
            raise RuntimeError("Scapy not available")

        ts = time.time()
        try:
            summary = pkt.summary() if hasattr(pkt, "summary") else str(pkt)
        except Exception:
            summary = "<unserializable-packet>"

        try:
            if self.packet_callback:
                self.packet_callback(summary)
        except Exception:
            self.logger.debug("Packet callback failed", exc_info=True)

        try:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                tcp = pkt[TCP]
                ip = pkt[IP]
                flags = tcp.flags
                syn_only = False
                try:
                    syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
                except Exception:
                    syn_only = 'S' in str(flags) and 'A' not in str(flags)

                if syn_only:
                    src = ip.src
                    dst_port = int(tcp.dport)
                    self.tcp_syns[src].append((ts, dst_port))
                    self._prune_old(self.tcp_syns[src], self.port_window)
                    unique_ports = {p for (_t, p) in self.tcp_syns[src]}
                    if len(unique_ports) >= self.port_threshold:
                        self.alert(f"Port scan detected from {src}: {len(unique_ports)} distinct ports in {self.port_window}s")

            if pkt.haslayer(ICMP) and pkt.haslayer(IP):
                icmp = pkt[ICMP]
                ip = pkt[IP]
                try:
                    icmp_type = int(icmp.type)
                except Exception:
                    icmp_type = None

                if icmp_type == 8:
                    src = ip.src
                    self.icmp_requests[src].append(ts)
                    self._prune_old(self.icmp_requests[src], self.ping_window)
                    if len(self.icmp_requests[src]) >= self.ping_threshold:
                        self.alert(f"Ping flood detected from {src}: {len(self.icmp_requests[src])} ICMP Echo Requests in {self.ping_window}s")
        except Exception as e:
            self.logger.debug("Error processing packet", exc_info=True)

    def alert(self, message: str):
        self.logger.warning(message)
        try:
            if self.alert_callback:
                self.alert_callback(message)
        except Exception:
            self.logger.debug("Alert callback error", exc_info=True)

    def start_live_async(self, interface=None, bpf_filter=None):
        # Prefer AsyncSniffer when available (non-blocking native implementation)
        if AsyncSniffer is not None:
            if self._sniffer is not None:
                return
            self._sniffer = AsyncSniffer(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)
            self._sniffer.start()
            return

        # Fallback: use scapy.sniff in a background thread with a stop event.
        if sniff is None:
            raise RuntimeError("No sniff implementation available (scapy missing)")
        if self._sniffer is not None:
            return

        self._stop_event = threading.Event()

        def _thread_target():
            try:
                # stop_filter is evaluated for every packet; when it returns True sniff stops.
                sniff(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False,
                      stop_filter=lambda pkt: self._stop_event.is_set())
            except Exception:
                # Log but keep thread from crashing silently
                try:
                    self.logger.debug("Fallback sniff thread error", exc_info=True)
                except Exception:
                    pass

        t = threading.Thread(target=_thread_target, daemon=True)
        self._sniffer = t
        t.start()

    def stop_live_async(self):
        # Stop either AsyncSniffer or the fallback thread
        if self._sniffer is None:
            return

        # If _sniffer is an AsyncSniffer-like object, it should have stop()
        try:
            stop = getattr(self._sniffer, "stop", None)
            if callable(stop):
                stop()
                self._sniffer = None
                return
        except Exception:
            self.logger.debug("Error stopping AsyncSniffer", exc_info=True)

        # Otherwise assume fallback thread: signal event and join
        try:
            if self._stop_event is not None:
                self._stop_event.set()
            if isinstance(self._sniffer, threading.Thread):
                self._sniffer.join(timeout=2)
            self._sniffer = None
            self._stop_event = None
        except Exception:
            self.logger.debug("Error stopping fallback sniffer thread", exc_info=True)

    def run_pcap(self, pcap_path):
        if rdpcap is None:
            raise RuntimeError("rdpcap not available")
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            try:
                self.process_packet(pkt)
            except Exception:
                self.logger.debug("Error processing pcap packet", exc_info=True)
