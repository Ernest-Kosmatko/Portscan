import socket
import threading

import pytest

from portscan import parse_ports, scan_host


def test_parse_single_and_list():
    assert parse_ports("80,22,80") == [22, 80]


def test_parse_range():
    assert parse_ports("20-23") == [20, 21, 22, 23]


def test_parse_top_is_sorted_and_nonempty():
    ports = parse_ports("top")
    assert ports == sorted(ports) and 443 in ports


@pytest.mark.parametrize("bad", ["0", "70000", "10-5", "abc"])
def test_parse_rejects_invalid(bad):
    with pytest.raises(ValueError):
        parse_ports(bad)


def _start_server(banner: bytes):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            conn.sendall(banner)
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv


def test_detects_open_port_and_banner():
    srv = _start_server(b"SSH-2.0-TestServer\r\n")
    port = srv.getsockname()[1]
    try:
        results = scan_host("127.0.0.1", [port], timeout=1.0, threads=4)
    finally:
        srv.close()
    assert [r.port for r in results] == [port]
    assert results[0].banner == "SSH-2.0-TestServer"


def test_closed_port_not_reported():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()
    assert scan_host("127.0.0.1", [port], timeout=0.5, threads=2) == []
