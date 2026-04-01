# Packet Analyzer (Scapy + Python)

This small project provides a lightweight packet analyzer that detects two common suspicious patterns:

- Port scans: multiple TCP SYNs from a single source to many distinct destination ports within a short time window.
- Ping floods: many ICMP Echo Requests (type 8) from a single source within a short time window.

Files added
- `packet_analyzer.py` — main analyzer with CLI, sliding-window detection, and alert logging.
- `requirements.txt` — lists runtime dependency (scapy).

Quick start

1. Install dependencies (recommended inside a venv):

```powershell
python -m pip install -r "requirements.txt"
```

2. Run live on an interface (may require elevated privileges):

```powershell
python packet_analyzer.py --interface "Ethernet" --filter "tcp or icmp"
```

3. Or analyze a pcap file:

```powershell
python packet_analyzer.py --pcap sample.pcap
```

Configuration

- `--port-threshold` (default 20): number of distinct TCP destination ports within the port-window that triggers a port-scan alert.
- `--port-window` (default 10s): sliding window (seconds) for port-scan detection.
- `--ping-threshold` (default 100): number of ICMP Echo Requests within the ping-window that triggers a ping-flood alert.
- `--ping-window` (default 5s): sliding window (seconds) for ping-flood detection.

Alerts

Alerts are printed to stdout and appended to `alerts.log` (created next to where you run the script).

Notes & next steps

- This is a simple heuristic-based detector intended for demonstration and small-scale monitoring. It's not a replacement for production IDS/IPS.
- Next improvements: configurable alert sinks (email/webhook), better state management for high-throughput capture (use counters rather than deques), and unit tests that feed synthetic/scapy-generated packets.

## Disclaimer

**Please Note:** If you download and use this software, I am not responsible for any effects or damages it may have on your computer or system. Use it at your own risk.
