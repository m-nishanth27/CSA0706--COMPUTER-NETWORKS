"""
analysis_metrics.py
--------------------
Post-processing script used to compute network performance metrics
(throughput, average delay, jitter, packet loss %, response time)
from packet-capture / simulator export logs (CSV format).

Expected input CSV columns (exported from Wireshark / Packet Tracer /
GNS3 capture, per topology and per traffic scenario):
    packet_id, src, dst, protocol, sent_time_ms, recv_time_ms,
    size_bytes, delivered (1/0)

Usage:
    python analysis_metrics.py capture_star_peak.csv
"""

import csv
import sys
from collections import defaultdict


def load_capture(path):
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["sent_time_ms"] = float(row["sent_time_ms"])
            row["recv_time_ms"] = float(row["recv_time_ms"]) if row["recv_time_ms"] else None
            row["size_bytes"] = float(row["size_bytes"])
            row["delivered"] = int(row["delivered"])
            rows.append(row)
    return rows


def compute_metrics(rows):
    metrics = {}
    total_packets = len(rows)
    delivered = [r for r in rows if r["delivered"] == 1]
    lost = total_packets - len(delivered)

    metrics["packet_loss_percent"] = round((lost / total_packets) * 100, 2) if total_packets else 0.0

    delays = [r["recv_time_ms"] - r["sent_time_ms"] for r in delivered if r["recv_time_ms"] is not None]
    metrics["avg_delay_ms"] = round(sum(delays) / len(delays), 2) if delays else 0.0

    # Jitter = mean absolute difference between consecutive delays
    jitter_vals = [abs(delays[i] - delays[i - 1]) for i in range(1, len(delays))]
    metrics["avg_jitter_ms"] = round(sum(jitter_vals) / len(jitter_vals), 2) if jitter_vals else 0.0

    if delivered:
        duration_s = (max(r["recv_time_ms"] for r in delivered) -
                      min(r["sent_time_ms"] for r in delivered)) / 1000.0
        total_bits = sum(r["size_bytes"] for r in delivered) * 8
        metrics["throughput_mbps"] = round((total_bits / duration_s) / 1e6, 2) if duration_s > 0 else 0.0
    else:
        metrics["throughput_mbps"] = 0.0

    # Per-protocol response time (mean delay grouped by protocol)
    per_protocol = defaultdict(list)
    for r in delivered:
        if r["recv_time_ms"] is not None:
            per_protocol[r["protocol"]].append(r["recv_time_ms"] - r["sent_time_ms"])
    metrics["per_protocol_response_ms"] = {
        proto: round(sum(v) / len(v), 2) for proto, v in per_protocol.items()
    }

    metrics["total_packets"] = total_packets
    metrics["delivered_packets"] = len(delivered)
    return metrics


def main():
    if len(sys.argv) != 2:
        print("Usage: python analysis_metrics.py <capture_csv_path>")
        sys.exit(1)

    rows = load_capture(sys.argv[1])
    result = compute_metrics(rows)

    print(f"\nPerformance Summary for: {sys.argv[1]}")
    print("-" * 45)
    for key, value in result.items():
        print(f"{key:28s}: {value}")


if __name__ == "__main__":
    main()
