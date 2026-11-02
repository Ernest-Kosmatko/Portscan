from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import Iterable

# Ports most often exposed on internet-facing hosts.
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 5985,
    6379, 8000, 8080, 8443, 9200, 11211, 27017,
]

# Protocols that stay silent until the client talks first.
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n"
HTTP_PORTS = {80, 8000, 8080, 8443, 3000}


@dataclass
class PortResult:
    port: int
    state: str
    service: str = ""
    banner: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def parse_ports(spec: str) -> list[int]:
    """Turn '22,80,8000-8100' or 'top' into a sorted list of unique ports."""
    spec = spec.strip().lower()
    if spec == "top":
        return sorted(TOP_PORTS)

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"invalid range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    for p in ports:
        if not 1 <= p <= 65535:
            raise ValueError(f"port out of range: {p}")
    return sorted(ports)


def _service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def _grab_banner(sock: socket.socket, host: str, port: int) -> str:
    try:
        if port in HTTP_PORTS:
            sock.sendall(HTTP_PROBE % host.encode())
        data = sock.recv(256)
    except OSError:
        return ""
    text = data.decode("utf-8", errors="replace").strip()
    return text.splitlines()[0][:120] if text else ""


def scan_port(host: str, port: int, timeout: float, grab_banner: bool) -> PortResult | None:
    """Return a PortResult for an open port, None otherwise."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = _grab_banner(sock, host, port) if grab_banner else ""
            return PortResult(port, "open", _service_name(port), banner)
    except OSError:
        return None


def scan_host(
    host: str,
    ports: Iterable[int],
    timeout: float = 1.0,
    threads: int = 100,
    grab_banner: bool = True,
) -> list[PortResult]:
    """Scan ports on a single host and return open ones sorted by port."""
    ip = socket.gethostbyname(host)
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(scan_port, ip, p, timeout, grab_banner) for p in ports]
        results = [f.result() for f in futures]
    return sorted((r for r in results if r), key=lambda r: r.port)
