#!/usr/bin/env python3
"""
RaGenLLM - Main Orchestrator

This script coordinates the full RaGenLLM pipeline.
Currently, it handles:
    - Nmap scanning
    - HTTP probing
    - Optional Nuclei scanning
    - Optional SQLMap-light scanning

Future extensions will add:
    - Retrieval (RAG)
    - PoC generation
    - Sandbox execution
    - Refinement loop
"""

import argparse
import json
from pathlib import Path

from scanner import Scanner


def parse_args():
    parser = argparse.ArgumentParser(description="RaGenLLM - Automated PoC Generation Framework (scanner stage)")
    parser.add_argument("--ip", required=True, help="Target IP or hostname")
    parser.add_argument("--ports", default="1-10000", help="Ports to scan (default: 1-10000)")
    parser.add_argument("--fast", action="store_true", help="Fast mode (skip Nuclei and SQLMap)")
    parser.add_argument("--no-nuclei", action="store_true", help="Disable Nuclei even if not in fast mode")
    parser.add_argument("--sqlmap", action="store_true", help="Enable SQLMap-light on candidate URLs")
    parser.add_argument("--out", default="scan_results.json", help="Path to output JSON file")

    return parser.parse_args()


def print_services_summary(services):
    print("\n========== SCAN SUMMARY ==========")
    for idx, s in enumerate(services, start=1):
        print(f"\n[{idx}] {s.get('ip')}:{s.get('port')}")
        print(f"  Product: {s.get('normalized_product') or s.get('product')}")
        print(f"  Version: {s.get('version')}")
        print(f"  Confidence: {s.get('confidence')}/10")
        print(f"  HTTP reachable: {(s.get('http_probe') or {}).get('reachable')}")
        if s.get("cves"):
            print(f"  CVEs: {', '.join(s['cves'])}")
        if s.get("nuclei_findings"):
            print(f"  Nuclei findings: {len(s['nuclei_findings'])}")


def main():
    args = parse_args()

    print("\n=== RaGenLLM :: Scanner Stage ===")
    print(f"Target  : {args.ip}")
    print(f"Ports   : {args.ports}")
    print(f"Fast    : {args.fast}")
    print(f"Nuclei  : {not args.no_nuclei}")
    print(f"SQLMap  : {args.sqlmap}")

    scanner = Scanner(
        enable_nuclei=not args.no_nuclei and not args.fast,
        enable_sqlmap=args.sqlmap and not args.fast,
        fast=args.fast,
    )

    services, sqli_bundle = scanner.run(args.ip, args.ports)

    print_services_summary(services)

    # ---- Save results ----
    output_path = Path(args.out)
    payload = {
        "target": args.ip,
        "ports": args.ports,
        "services": services,
        "sqli_bundle": sqli_bundle,
    }

    output_path.write_text(json.dumps(payload, indent=2))
    print(f"\nResults saved to: {output_path.resolve()}")


if __name__ == "__main__":
    main()
