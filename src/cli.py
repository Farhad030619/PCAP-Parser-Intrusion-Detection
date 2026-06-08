import argparse
import logging
import os
import sys
from typing import Dict, Any

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scapy.all import sniff
from scapy.utils import PcapReader
from src.analyzer import NetworkAnalyzer


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Intrusion Detection System (IDS) PCAP Analyzer"
    )
    parser.add_argument(
        "pcap_file",
        nargs="?",
        help="Path to the PCAP file to analyze"
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Sniff network traffic live in real-time"
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to sniff on (e.g. eth0, en0)"
    )
    parser.add_argument(
        "--syn-threshold",
        type=int,
        default=100,
        help="Minimum number of SYN packets sent by an IP to consider a SYN flood"
    )
    parser.add_argument(
        "--syn-ratio",
        type=float,
        default=10.0,
        help="Minimum ratio of SYN to SYN-ACK packets to trigger SYN flood alert"
    )
    parser.add_argument(
        "-o",
        "--output-log",
        default="ids_alerts.log",
        help="Path to the output log file for saving alerts"
    )

    args = parser.parse_args()

    if not args.pcap_file and not args.live:
        print("Error: Either a PCAP file or the --live flag must be specified.", file=sys.stderr)
        sys.exit(1)
    if args.pcap_file and args.live:
        print("Error: Cannot specify both a PCAP file and --live mode.", file=sys.stderr)
        sys.exit(1)

    logger = logging.getLogger("ids_alerts")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("\033[91m[ALERT] %(message)s\033[0m")
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    try:
        file_handler = logging.FileHandler(args.output_log)
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter("%(asctime)s - [ALERT] %(message)s")
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Error: Unable to initialize log file '{args.output_log}': {e}", file=sys.stderr)
        sys.exit(1)

    def log_alert(alert: Dict[str, Any]) -> None:
        logger.info(alert["message"])

    analyzer = NetworkAnalyzer(
        syn_flood_threshold=args.syn_threshold,
        syn_flood_ratio=args.syn_ratio,
        on_alert=log_alert,
    )

    if args.live:
        iface_desc = args.interface if args.interface else "default interface"
        print(f"\033[96mStarting live network sniffing... (Press Ctrl+C to stop) on {iface_desc}\033[0m")
        try:
            sniff(iface=args.interface, prn=analyzer.process_packet, store=False)
        except KeyboardInterrupt:
            print("\n\033[92mStopping live sniffing...\033[0m")
    else:
        print(f"\033[96mAnalyzing PCAP file: {args.pcap_file}...\033[0m")
        try:
            with PcapReader(args.pcap_file) as reader:
                for packet in reader:
                    analyzer.process_packet(packet)
                    if analyzer.packet_count % 1000 == 0:
                        print(f"\033[96mProcessed {analyzer.packet_count} packets...\033[0m")
        except FileNotFoundError:
            print(f"Error: File '{args.pcap_file}' not found.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading/parsing PCAP file: {e}", file=sys.stderr)
            sys.exit(1)

    analyzer.evaluate_syn_floods()

    packet_count = analyzer.packet_count
    total_alerts = len(analyzer.alerts)
    summary = (
        f"Analysis completed. {total_alerts} alerts written to {args.output_log}\n"
        f"Total packets analyzed: {packet_count}\n"
        f"Total alerts triggered: {total_alerts}"
    )
    print(f"\033[92m{summary}\033[0m")


if __name__ == "__main__":
    main()
