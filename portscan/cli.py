from __future__ import annotations

import argparse
import json
import socket
import sys
import time

from .scanner import parse_ports, scan_host


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portscan",
        description="TCP connect scanner. Use only on systems you are authorized to test.",
    )
    p.add_argument("host", help="hostname or IPv4 address")
    p.add_argument("-p", "--ports", default="top",
                   help="ports: '22,80', '1-1024' or 'top' (default: top)")
    p.add_argument("-t", "--timeout", type=float, default=1.0,
                   help="connect timeout in seconds (default: 1.0)")
    p.add_argument("-T", "--threads", type=int, default=100,
                   help="worker threads (default: 100)")
    p.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    p.add_argument("-o", "--output", choices=["table", "json"], default="table")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    start = time.perf_counter()
    try:
        results = scan_host(args.host, ports, args.timeout, args.threads, not args.no_banner)
    except socket.gaierror:
        print(f"error: cannot resolve {args.host}", file=sys.stderr)
        return 1
    elapsed = time.perf_counter() - start

    if args.output == "json":
        print(json.dumps({
            "host": args.host,
            "scanned": len(ports),
            "elapsed_s": round(elapsed, 2),
            "open": [r.to_dict() for r in results],
        }, indent=2))
        return 0

    print(f"Scan of {args.host}: {len(ports)} ports in {elapsed:.2f}s")
    if not results:
        print("No open ports found.")
        return 0
    print(f"{'PORT':<8}{'SERVICE':<14}BANNER")
    for r in results:
        print(f"{r.port:<8}{r.service or '-':<14}{r.banner}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
