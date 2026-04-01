#!/usr/bin/env python3
"""
Lightweight network packet analyzer using Scapy.

Detects simple port scans (many distinct TCP SYN destination ports from the
same source in a short time window) and ICMP ping floods (many ICMP Echo
Requests from the same source in a short time window).

This module exposes PacketAnalyzer which can be used from a CLI or a GUI.
"""
import argparse
import logging
import time
from collections import defaultdict, deque

try:
    # import scapy at runtime to avoid import errors in editors without scapy
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
    """Analyze packets for simple port-scan and ping-flood heuristics.

    Optional callbacks:
      - alert_callback(message: str)  -> called when an alert is generated
      - packet_callback(summary: str) -> called for every captured packet
    """

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

        # Optional callbacks
        self.alert_callback = alert_callback
        self.packet_callback = packet_callback

        # AsyncSniffer instance for managed live capture (if available)
        self._sniffer = None

        # state for heuristics
        self.tcp_syns = defaultdict(deque)    # src_ip -> deque[(ts, dst_port)]
        self.icmp_requests = defaultdict(deque)  # src_ip -> deque[ts]

        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s",
                            handlers=[logging.FileHandler(alert_log_path), logging.StreamHandler()])
        self.logger = logging.getLogger("packet_analyzer")

    def _prune_old(self, dq: deque, window: float):
        cutoff = time.time() - window
        # entries may be tuples (ts, port) or scalar timestamps
        while dq and (dq[0][0] < cutoff if isinstance(dq[0], tuple) else dq[0] < cutoff):
            dq.popleft()

    def process_packet(self, pkt):
        """Process a single scapy packet-like object.

        This method is safe to call from scapy's sniff/prn handler.
        """
        if IP is None:
            raise RuntimeError("Scapy not available. Install scapy to run this analyzer.")

        ts = time.time()

        # Deliver a short summary to any packet callback first (non-blocking best-effort)
        try:
            summary = pkt.summary() if hasattr(pkt, "summary") else str(pkt)
        except Exception:
            summary = "<unserializable-packet>"

        try:
            if self.packet_callback:
                self.packet_callback(summary)
        except Exception:
            try:
                self.logger.debug("Packet callback raised an exception", exc_info=True)
            except Exception:
                pass

        # TCP SYN detection (possible port scans)
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

            # ICMP echo request detection (ping flood)
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
            # keep analyzer robust
            try:
                self.logger.debug(f"Error in process_packet: {e}", exc_info=True)
            except Exception:
                pass

    def alert(self, message: str):
        self.logger.warning(message)
        try:
            if self.alert_callback:
                self.alert_callback(message)
        except Exception:
            try:
                self.logger.debug("Alert callback raised an exception", exc_info=True)
            except Exception:
                pass

    def run_live(self, interface=None, bpf_filter=None):
        if sniff is None:
            raise RuntimeError("Scapy not available. Install scapy to capture packets (pip install scapy)")
        self.logger.info(f"Starting live capture on interface={interface} filter={bpf_filter}")
        sniff(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)

    def start_live_async(self, interface=None, bpf_filter=None):
        if AsyncSniffer is None:
            raise RuntimeError("AsyncSniffer not available. Install scapy with AsyncSniffer support.")
        if self._sniffer is not None:
            self.logger.info("Async sniffer already running")
            return
        self._sniffer = AsyncSniffer(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)
        self._sniffer.start()
        self.logger.info("Async live capture started")

    def stop_live_async(self, timeout=2):
        if self._sniffer is None:
            self.logger.info("No async sniffer to stop")
            return
        try:
            self._sniffer.stop()
            self._sniffer = None
            self.logger.info("Async live capture stopped")
        except Exception as e:
            try:
                self.logger.debug(f"Error stopping async sniffer: {e}")
            except Exception:
                pass

    def run_pcap(self, pcap_path):
        if rdpcap is None:
            raise RuntimeError("Scapy not available. Install scapy to read pcap files (pip install scapy)")
        self.logger.info(f"Reading pcap file {pcap_path}")
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            try:
                self.process_packet(pkt)
            except Exception as e:
                try:
                    self.logger.debug(f"Error processing packet: {e}")
                except Exception:
                    pass


def build_arg_parser():
    p = argparse.ArgumentParser(description="Simple packet analyzer to detect port scans and ping floods")
    p.add_argument("--interface", "-i", help="Network interface for live capture (mutually exclusive with --pcap)")
    p.add_argument("--pcap", "-r", help="Read packets from pcap file instead of live capture")
    p.add_argument("--port-threshold", type=int, default=20, help="Number of distinct TCP destination ports in window to trigger port-scan alert")
    p.add_argument("--port-window", type=float, default=10.0, help="Sliding window (seconds) for port-scan detection")
    p.add_argument("--ping-threshold", type=int, default=100, help="Number of ICMP Echo Requests in window to trigger ping-flood alert")
    p.add_argument("--ping-window", type=float, default=5.0, help="Sliding window (seconds) for ping-flood detection")
    p.add_argument("--filter", "-f", help="BPF filter for live capture (e.g., 'tcp or icmp')")
    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    analyzer = PacketAnalyzer(port_threshold=args.port_threshold,
                              port_window=args.port_window,
                              ping_threshold=args.ping_threshold,
                              ping_window=args.ping_window)

    if args.pcap:
        analyzer.run_pcap(args.pcap)
    else:
        analyzer.run_live(interface=args.interface, bpf_filter=args.filter)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Lightweight network packet analyzer using Scapy.

Detects simple port scans (many distinct TCP SYN destination ports from the
same source in a short time window) and ICMP ping floods (many ICMP Echo
Requests from the same source in a short time window).

This module exposes PacketAnalyzer which can be used from a CLI or a GUI.
"""
import argparse
import logging
import time
from collections import defaultdict, deque

try:
    # import scapy at runtime to avoid import errors in editors without scapy
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
    """Analyze packets for simple port-scan and ping-flood heuristics.

    Optional callbacks:
      - alert_callback(message: str)  -> called when an alert is generated
      - packet_callback(summary: str) -> called for every captured packet
    """

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

        # Optional callbacks
        self.alert_callback = alert_callback
        self.packet_callback = packet_callback

        # AsyncSniffer instance for managed live capture (if available)
        self._sniffer = None

        # state for heuristics
        self.tcp_syns = defaultdict(deque)    # src_ip -> deque[(ts, dst_port)]
        self.icmp_requests = defaultdict(deque)  # src_ip -> deque[ts]

        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s",
                            handlers=[logging.FileHandler(alert_log_path), logging.StreamHandler()])
        self.logger = logging.getLogger("packet_analyzer")

    def _prune_old(self, dq: deque, window: float):
        cutoff = time.time() - window
        # entries may be tuples (ts, port) or scalar timestamps
        while dq and (dq[0][0] < cutoff if isinstance(dq[0], tuple) else dq[0] < cutoff):
            dq.popleft()

    def process_packet(self, pkt):
        """Process a single scapy packet-like object.

        This method is safe to call from scapy's sniff/prn handler.
        """
        if IP is None:
            raise RuntimeError("Scapy not available. Install scapy to run this analyzer.")

        ts = time.time()

        # Deliver a short summary to any packet callback first (non-blocking best-effort)
        try:
            summary = pkt.summary() if hasattr(pkt, "summary") else str(pkt)
        except Exception:
            summary = "<unserializable-packet>"

        try:
            if self.packet_callback:
                self.packet_callback(summary)
        except Exception:
            try:
                self.logger.debug("Packet callback raised an exception", exc_info=True)
            except Exception:
                pass

        # TCP SYN detection (possible port scans)
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

            # ICMP echo request detection (ping flood)
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
            # keep analyzer robust
            try:
                self.logger.debug(f"Error in process_packet: {e}", exc_info=True)
            except Exception:
                pass

    def alert(self, message: str):
        self.logger.warning(message)
        try:
            if self.alert_callback:
                self.alert_callback(message)
        except Exception:
            try:
                self.logger.debug("Alert callback raised an exception", exc_info=True)
            except Exception:
                pass

    def run_live(self, interface=None, bpf_filter=None):
        if sniff is None:
            raise RuntimeError("Scapy not available. Install scapy to capture packets (pip install scapy)")
        self.logger.info(f"Starting live capture on interface={interface} filter={bpf_filter}")
        sniff(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)

    def start_live_async(self, interface=None, bpf_filter=None):
        if AsyncSniffer is None:
            raise RuntimeError("AsyncSniffer not available. Install scapy with AsyncSniffer support.")
        if self._sniffer is not None:
            self.logger.info("Async sniffer already running")
            return
        self._sniffer = AsyncSniffer(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)
        self._sniffer.start()
        self.logger.info("Async live capture started")

    def stop_live_async(self, timeout=2):
        if self._sniffer is None:
            self.logger.info("No async sniffer to stop")
            return
        try:
            self._sniffer.stop()
            self._sniffer = None
            self.logger.info("Async live capture stopped")
        except Exception as e:
            try:
                self.logger.debug(f"Error stopping async sniffer: {e}")
            except Exception:
                pass

    def run_pcap(self, pcap_path):
        if rdpcap is None:
            raise RuntimeError("Scapy not available. Install scapy to read pcap files (pip install scapy)")
        self.logger.info(f"Reading pcap file {pcap_path}")
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            try:
                self.process_packet(pkt)
            except Exception as e:
                try:
                    self.logger.debug(f"Error processing packet: {e}")
                except Exception:
                    pass


def build_arg_parser():
    p = argparse.ArgumentParser(description="Simple packet analyzer to detect port scans and ping floods")
    p.add_argument("--interface", "-i", help="Network interface for live capture (mutually exclusive with --pcap)")
    p.add_argument("--pcap", "-r", help="Read packets from pcap file instead of live capture")
    p.add_argument("--port-threshold", type=int, default=20, help="Number of distinct TCP destination ports in window to trigger port-scan alert")
    p.add_argument("--port-window", type=float, default=10.0, help="Sliding window (seconds) for port-scan detection")
    p.add_argument("--ping-threshold", type=int, default=100, help="Number of ICMP Echo Requests in window to trigger ping-flood alert")
    p.add_argument("--ping-window", type=float, default=5.0, help="Sliding window (seconds) for ping-flood detection")
    p.add_argument("--filter", "-f", help="BPF filter for live capture (e.g., 'tcp or icmp')")
    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    analyzer = PacketAnalyzer(port_threshold=args.port_threshold,
                              port_window=args.port_window,
                              ping_threshold=args.ping_threshold,
                              ping_window=args.ping_window)

    if args.pcap:
        analyzer.run_pcap(args.pcap)
    else:
        analyzer.run_live(interface=args.interface, bpf_filter=args.filter)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Lightweight network packet analyzer using Scapy.

Detects simple port scans (many distinct TCP SYN destination ports from the
same source in a short time window) and ICMP ping floods (many ICMP Echo
Requests from the same source in a short time window).

Usage examples:
  python packet_analyzer.py --interface eth0
  python packet_analyzer.py --pcap sample.pcap --port-threshold 30

This script logs alerts to `alerts.log` and prints them to stdout.
"""
import argparse
import logging
import time
from collections import defaultdict, deque

try:
    # scapy imports are only required at runtime; avoid static import resolution errors in editors/linters
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

        # Optional callback to receive alert messages (for GUI integration)
        # Signature: callback(message: str)
        self.alert_callback = alert_callback

        # Optional callback to receive every packet (for GUI live display)
        # Signature: callback(packet_summary: str)
        self.packet_callback = packet_callback

        # AsyncSniffer instance for managed live capture (if available)
        self._sniffer = None

        # For port scans: map src_ip -> deque of (timestamp, dst_port)
        self.tcp_syns = defaultdict(deque)

        # For ping flood: map src_ip -> deque of timestamps of ICMP echo requests
        self.icmp_requests = defaultdict(deque)

        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s",
                            handlers=[logging.FileHandler(alert_log_path), logging.StreamHandler()])
        self.logger = logging.getLogger("packet_analyzer")

    def _prune_old(self, dq: deque, window: float):
        cutoff = time.time() - window
        while dq and (dq[0][0] < cutoff if isinstance(dq[0], tuple) else dq[0] < cutoff):
            dq.popleft()

    def process_packet(self, pkt):
        """Process a single scapy packet-like object."""
        # Only attempt to access layers if scapy is present
        if IP is None:
            raise RuntimeError("Scapy not available. Install scapy to run live captures: pip install scapy")

        ts = time.time()

        # If the caller wants every packet, give them a short summary string
        try:
            summary = pkt.summary() if hasattr(pkt, "summary") else str(pkt)
        except Exception:
            try:
                summary = str(pkt)
            except Exception:
                summary = "<unserializable-packet>"

        try:
            if self.packet_callback:
                # deliver packet summary (non-blocking callers should handle UI thread marshalling)
                self.packet_callback(summary)
        except Exception:
            # don't let packet callbacks break analysis
            try:
                self.logger.debug("Packet callback raised an exception", exc_info=True)
            except Exception:
                pass

        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            # Detect TCP SYNs (possible port scan behavior)
            tcp = pkt[TCP]
            ip = pkt[IP]
            flags = tcp.flags
            # SYN flag present and not SYN-ACK (SYN without ACK)
            # In Scapy flags can be an int or string; check for flag value 0x02
            syn_only = False
            try:
                syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
            except Exception:
                syn_only = 'S' in str(flags) and 'A' not in str(flags)

            if syn_only:
                src = ip.src
                dst_port = int(tcp.dport)
                self.tcp_syns[src].append((ts, dst_port))
                # prune old entries
                self._prune_old(self.tcp_syns[src], self.port_window)

                # Compute unique destination ports in the sliding window
                unique_ports = {p for (_t, p) in self.tcp_syns[src]}
                if len(unique_ports) >= self.port_threshold:
                    self.alert(f"Port scan detected from {src}: {len(unique_ports)} distinct ports in {self.port_window}s")

        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            icmp = pkt[ICMP]
            ip = pkt[IP]
            # ICMP type 8 is Echo Request
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

    def alert(self, message: str):
        # Log alert and also print (logging configured to file + stdout)
        self.logger.warning(message)
        # If a callback is provided (e.g., GUI), call it
        try:
            if self.alert_callback:
                self.alert_callback(message)
        except Exception:
            try:
                self.logger.debug("Alert callback raised an exception", exc_info=True)
            except Exception:
                pass

    def run_live(self, interface=None, bpf_filter=None):
        if sniff is None:
            raise RuntimeError("Scapy not available. Install scapy to capture packets (pip install scapy)")

        self.logger.info(f"Starting live capture on interface={interface} filter={bpf_filter}")
        # sniff is blocking; expose as a call that can be run in a thread by the caller
        sniff(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)

    def start_live_async(self, interface=None, bpf_filter=None):
        """Start a non-blocking live capture using AsyncSniffer when available."""
        if AsyncSniffer is None:
            raise RuntimeError("AsyncSniffer not available. Install scapy with AsyncSniffer support.")
        if self._sniffer is not None:
            self.logger.info("Async sniffer already running")
            return
        self._sniffer = AsyncSniffer(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)
        self._sniffer.start()
        self.logger.info("Async live capture started")

    def stop_live_async(self, timeout=2):
        """Stop an AsyncSniffer if running."""
        if self._sniffer is None:
            self.logger.info("No async sniffer to stop")
            return
        try:
            self._sniffer.stop()
            self._sniffer = None
            self.logger.info("Async live capture stopped")
        except Exception as e:
            try:
                self.logger.debug(f"Error stopping async sniffer: {e}")
            except Exception:
                pass

    def run_pcap(self, pcap_path):
        if rdpcap is None:
            raise RuntimeError("Scapy not available. Install scapy to read pcap files (pip install scapy)")

        self.logger.info(f"Reading pcap file {pcap_path}")
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            try:
                self.process_packet(pkt)
            except Exception as e:
                try:
                    self.logger.debug(f"Error processing packet: {e}")
                except Exception:
                    pass


def build_arg_parser():
    p = argparse.ArgumentParser(description="Simple packet analyzer to detect port scans and ping floods")
    p.add_argument("--interface", "-i", help="Network interface for live capture (mutually exclusive with --pcap)")
    p.add_argument("--pcap", "-r", help="Read packets from pcap file instead of live capture")
    p.add_argument("--port-threshold", type=int, default=20, help="Number of distinct TCP destination ports in window to trigger port-scan alert")
    p.add_argument("--port-window", type=float, default=10.0, help="Sliding window (seconds) for port-scan detection")
    p.add_argument("--ping-threshold", type=int, default=100, help="Number of ICMP Echo Requests in window to trigger ping-flood alert")
    p.add_argument("--ping-window", type=float, default=5.0, help="Sliding window (seconds) for ping-flood detection")
    p.add_argument("--filter", "-f", help="BPF filter for live capture (e.g., 'tcp or icmp')")
    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    analyzer = PacketAnalyzer(port_threshold=args.port_threshold,
                              port_window=args.port_window,
                              ping_threshold=args.ping_threshold,
                              ping_window=args.ping_window)

    if args.pcap:
        analyzer.run_pcap(args.pcap)
    else:
        # If no interface provided, sniff() will use scapy's default
        analyzer.run_live(interface=args.interface, bpf_filter=args.filter)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Lightweight network packet analyzer using Scapy.

Detects simple port scans (many distinct TCP SYN destination ports from the
same source in a short time window) and ICMP ping floods (many ICMP Echo
Requests from the same source in a short time window).

Usage examples:
  python packet_analyzer.py --interface eth0
  python packet_analyzer.py --pcap sample.pcap --port-threshold 30

This script logs alerts to `alerts.log` and prints them to stdout.
"""
import argparse
import logging
import time
from collections import defaultdict, deque

try:
    # scapy imports are only required at runtime; avoid static import resolution errors in editors/linters
    import importlib
    _scapy_all = importlib.import_module("scapy.all")
    sniff = _scapy_all.sniff
    rdpcap = _scapy_all.rdpcap
    IP = _scapy_all.IP
    TCP = _scapy_all.TCP
    ICMP = _scapy_all.ICMP
    AsyncSniffer = getattr(_scapy_all, "AsyncSniffer", None)
except Exception:
    # Leave imports at top-level to make syntax checking possible without scapy installed.
    sniff = rdpcap = IP = TCP = ICMP = AsyncSniffer = None


class PacketAnalyzer:
    def __init__(self,
                 port_threshold=20,
                 port_window=10.0,
                 ping_threshold=100,
                 ping_window=5.0,
                 alert_log_path="alerts.log",
                 alert_callback=None):
        self.port_threshold = port_threshold
        self.port_window = port_window
        self.ping_threshold = ping_threshold
        self.ping_window = ping_window

        # Optional callback to receive alert messages (for GUI integration)
        # Signature: callback(message: str)
        self.alert_callback = alert_callback

        # AsyncSniffer instance for managed live capture (if available)
        self._sniffer = None

        # For port scans: map src_ip -> deque of (timestamp, dst_port)
        self.tcp_syns = defaultdict(deque)

        # For ping flood: map src_ip -> deque of timestamps of ICMP echo requests
        self.icmp_requests = defaultdict(deque)

        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s",
                            handlers=[logging.FileHandler(alert_log_path), logging.StreamHandler()])
        self.logger = logging.getLogger("packet_analyzer")

    def _prune_old(self, dq: deque, window: float):
        cutoff = time.time() - window
        while dq and (dq[0][0] < cutoff if isinstance(dq[0], tuple) else dq[0] < cutoff):
            dq.popleft()

    def process_packet(self, pkt):
        """Process a single scapy packet-like object."""
        # Only attempt to access layers if scapy is present
        if IP is None:
            raise RuntimeError("Scapy not available. Install scapy to run live captures: pip install scapy")

        ts = time.time()

        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            # Detect TCP SYNs (possible port scan behavior)
            tcp = pkt[TCP]
            ip = pkt[IP]
            flags = tcp.flags
            # SYN flag present and not SYN-ACK (SYN without ACK)
            # In Scapy flags can be an int or string; check for flag value 0x02
            syn_only = False
            try:
                syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
            except Exception:
                syn_only = 'S' in str(flags) and 'A' not in str(flags)

            if syn_only:
                src = ip.src
                dst_port = int(tcp.dport)
                self.tcp_syns[src].append((ts, dst_port))
                # prune old entries
                self._prune_old(self.tcp_syns[src], self.port_window)

                # Compute unique destination ports in the sliding window
                unique_ports = {p for (_t, p) in self.tcp_syns[src]}
                if len(unique_ports) >= self.port_threshold:
                    self.alert(f"Port scan detected from {src}: {len(unique_ports)} distinct ports in {self.port_window}s")

        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            icmp = pkt[ICMP]
            ip = pkt[IP]
            # ICMP type 8 is Echo Request
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

    def alert(self, message: str):
        # Log alert and also print (logging configured to file + stdout)
        self.logger.warning(message)
        # If a callback is provided (e.g., GUI), call it
        try:
            if self.alert_callback:
                self.alert_callback(message)
        except Exception:
            # Don't let callbacks break the analyzer
            self.logger.debug("Alert callback raised an exception", exc_info=True)

    def run_live(self, interface=None, bpf_filter=None):
        if sniff is None:
            raise RuntimeError("Scapy not available. Install scapy to capture packets (pip install scapy)")

        self.logger.info(f"Starting live capture on interface={interface} filter={bpf_filter}")
        # sniff is blocking; expose as a call that can be run in a thread by the caller
        sniff(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)

    def start_live_async(self, interface=None, bpf_filter=None):
        """Start a non-blocking live capture using AsyncSniffer when available."""
        if AsyncSniffer is None:
            raise RuntimeError("AsyncSniffer not available. Install scapy with AsyncSniffer support.")
        if self._sniffer is not None:
            self.logger.info("Async sniffer already running")
            return
        self._sniffer = AsyncSniffer(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)
        self._sniffer.start()
        self.logger.info("Async live capture started")

    def stop_live_async(self, timeout=2):
        """Stop an AsyncSniffer if running."""
        if self._sniffer is None:
            self.logger.info("No async sniffer to stop")
            return
        try:
            self._sniffer.stop()
            self._sniffer = None
            self.logger.info("Async live capture stopped")
        except Exception as e:
            self.logger.debug(f"Error stopping async sniffer: {e}")

    def run_pcap(self, pcap_path):
        if rdpcap is None:
            raise RuntimeError("Scapy not available. Install scapy to read pcap files (pip install scapy)")

        self.logger.info(f"Reading pcap file {pcap_path}")
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            try:
                self.process_packet(pkt)
            except Exception as e:
                # Don't stop on single-packet errors
                self.logger.debug(f"Error processing packet: {e}")


def build_arg_parser():
    p = argparse.ArgumentParser(description="Simple packet analyzer to detect port scans and ping floods")
    p.add_argument("--interface", "-i", help="Network interface for live capture (mutually exclusive with --pcap)")
    p.add_argument("--pcap", "-r", help="Read packets from pcap file instead of live capture")
    p.add_argument("--port-threshold", type=int, default=20, help="Number of distinct TCP destination ports in window to trigger port-scan alert")
    p.add_argument("--port-window", type=float, default=10.0, help="Sliding window (seconds) for port-scan detection")
    p.add_argument("--ping-threshold", type=int, default=100, help="Number of ICMP Echo Requests in window to trigger ping-flood alert")
    p.add_argument("--ping-window", type=float, default=5.0, help="Sliding window (seconds) for ping-flood detection")
    p.add_argument("--filter", "-f", help="BPF filter for live capture (e.g., 'tcp or icmp')")
    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    analyzer = PacketAnalyzer(port_threshold=args.port_threshold,
                              port_window=args.port_window,
                              ping_threshold=args.ping_threshold,
                              ping_window=args.ping_window)

    if args.pcap:
        analyzer.run_pcap(args.pcap)
    else:
        # If no interface provided, sniff() will use scapy's default
        analyzer.run_live(interface=args.interface, bpf_filter=args.filter)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Lightweight network packet analyzer using Scapy.

Detects simple port scans (many distinct TCP SYN destination ports from the
same source in a short time window) and ICMP ping floods (many ICMP Echo
Requests from the same source in a short time window).

Usage examples:
  python packet_analyzer.py --interface eth0
  python packet_analyzer.py --pcap sample.pcap --port-threshold 30

This script logs alerts to `alerts.log` and prints them to stdout.
"""
import argparse
import logging
import time
from collections import defaultdict, deque

try:
    # scapy imports are only required at runtime; avoid static import resolution errors in editors/linters
    import importlib
    _scapy_all = importlib.import_module("scapy.all")
    sniff = _scapy_all.sniff
    rdpcap = _scapy_all.rdpcap
    IP = _scapy_all.IP
    TCP = _scapy_all.TCP
    ICMP = _scapy_all.ICMP
    AsyncSniffer = getattr(_scapy_all, "AsyncSniffer", None)
except Exception:
    # Leave imports at top-level to make syntax checking possible without scapy installed.
    sniff = rdpcap = IP = TCP = ICMP = AsyncSniffer = None


class PacketAnalyzer:
    def __init__(self,
                 port_threshold=20,
                 port_window=10.0,
                 ping_threshold=100,
                 ping_window=5.0,
                 alert_log_path="alerts.log",
                 alert_callback=None):
        self.port_threshold = port_threshold
        self.port_window = port_window
        self.ping_threshold = ping_threshold
        self.ping_window = ping_window

        # Optional callback to receive alert messages (for GUI integration)
        # Signature: callback(message: str)
        self.alert_callback = alert_callback

        # AsyncSniffer instance for managed live capture (if available)
        self._sniffer = None

        # For port scans: map src_ip -> deque of (timestamp, dst_port)
        self.tcp_syns = defaultdict(deque)

        # For ping flood: map src_ip -> deque of timestamps of ICMP echo requests
        self.icmp_requests = defaultdict(deque)

        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s",
                            handlers=[logging.FileHandler(alert_log_path), logging.StreamHandler()])
        self.logger = logging.getLogger("packet_analyzer")

    def _prune_old(self, dq: deque, window: float):
        cutoff = time.time() - window
        while dq and dq[0][0] < cutoff if isinstance(dq[0], tuple) else dq[0] < cutoff:
            dq.popleft()

    def process_packet(self, pkt):
        """Process a single scapy packet-like object."""
        # Only attempt to access layers if scapy is present
        if IP is None:
            raise RuntimeError("Scapy not available. Install scapy to run live captures: pip install scapy")

        ts = time.time()

        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            # Detect TCP SYNs (possible port scan behavior)
            tcp = pkt[TCP]
            ip = pkt[IP]
            flags = tcp.flags
            # SYN flag present and not SYN-ACK (SYN without ACK)
            # In Scapy flags can be an int or string; check for flag value 0x02
            syn_only = False
            try:
                syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
            except Exception:
                syn_only = 'S' in str(flags) and 'A' not in str(flags)

            if syn_only:
                src = ip.src
                dst_port = int(tcp.dport)
                self.tcp_syns[src].append((ts, dst_port))
                # prune old entries
                self._prune_old(self.tcp_syns[src], self.port_window)

                # Compute unique destination ports in the sliding window
                unique_ports = {p for (_t, p) in self.tcp_syns[src]}
                if len(unique_ports) >= self.port_threshold:
                    self.alert(f"Port scan detected from {src}: {len(unique_ports)} distinct ports in {self.port_window}s")

        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            icmp = pkt[ICMP]
            ip = pkt[IP]
            # ICMP type 8 is Echo Request
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

    def alert(self, message: str):
        # Log alert and also print (logging configured to file + stdout)
        self.logger.warning(message)
        # If a callback is provided (e.g., GUI), call it
        try:
            if self.alert_callback:
                self.alert_callback(message)
        except Exception:
            # Don't let callbacks break the analyzer
            self.logger.debug("Alert callback raised an exception", exc_info=True)

    def run_live(self, interface=None, bpf_filter=None):
        if sniff is None:
            raise RuntimeError("Scapy not available. Install scapy to capture packets (pip install scapy)")

        self.logger.info(f"Starting live capture on interface={interface} filter={bpf_filter}")
        # sniff is blocking; expose as a call that can be run in a thread by the caller
        sniff(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)

    def start_live_async(self, interface=None, bpf_filter=None):
        """Start a non-blocking live capture using AsyncSniffer when available."""
        if AsyncSniffer is None:
            raise RuntimeError("AsyncSniffer not available. Install scapy with AsyncSniffer support.")
        if self._sniffer is not None:
            self.logger.info("Async sniffer already running")
            return
        self._sniffer = AsyncSniffer(iface=interface, prn=self.process_packet, filter=bpf_filter, store=False)
        self._sniffer.start()
        self.logger.info("Async live capture started")

    def stop_live_async(self, timeout=2):
        """Stop an AsyncSniffer if running."""
        if self._sniffer is None:
            self.logger.info("No async sniffer to stop")
            return
        try:
            self._sniffer.stop()
            self._sniffer = None
            self.logger.info("Async live capture stopped")
        except Exception as e:
            self.logger.debug(f"Error stopping async sniffer: {e}")

    def run_pcap(self, pcap_path):
        if rdpcap is None:
            raise RuntimeError("Scapy not available. Install scapy to read pcap files (pip install scapy)")

        self.logger.info(f"Reading pcap file {pcap_path}")
        pkts = rdpcap(pcap_path)
        for pkt in pkts:
            try:
                self.process_packet(pkt)
            except Exception as e:
                # Don't stop on single-packet errors
                self.logger.debug(f"Error processing packet: {e}")


def build_arg_parser():
    p = argparse.ArgumentParser(description="Simple packet analyzer to detect port scans and ping floods")
    p.add_argument("--interface", "-i", help="Network interface for live capture (mutually exclusive with --pcap)")
    p.add_argument("--pcap", "-r", help="Read packets from pcap file instead of live capture")
    p.add_argument("--port-threshold", type=int, default=20, help="Number of distinct TCP destination ports in window to trigger port-scan alert")
    p.add_argument("--port-window", type=float, default=10.0, help="Sliding window (seconds) for port-scan detection")
    p.add_argument("--ping-threshold", type=int, default=100, help="Number of ICMP Echo Requests in window to trigger ping-flood alert")
    p.add_argument("--ping-window", type=float, default=5.0, help="Sliding window (seconds) for ping-flood detection")
    p.add_argument("--filter", "-f", help="BPF filter for live capture (e.g., 'tcp or icmp')")
    return p


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    analyzer = PacketAnalyzer(port_threshold=args.port_threshold,
                              port_window=args.port_window,
                              ping_threshold=args.ping_threshold,
                              ping_window=args.ping_window)

    if args.pcap:
        analyzer.run_pcap(args.pcap)
    else:
        # If no interface provided, sniff() will use scapy's default
        analyzer.run_live(interface=args.interface, bpf_filter=args.filter)


if __name__ == "__main__":
    main()
