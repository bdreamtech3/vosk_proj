"""Print URLs/hosts found in outbound IPv4 HTTP and HTTPS packets on Windows."""

from __future__ import annotations

import argparse
import ipaddress
import selectors
import socket
import sys
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
Flow = tuple[str, int, str, int]


class RecentUrls:
    def __init__(self, ttl: float = 10.0, capacity: int = 2048) -> None:
        self.ttl = ttl
        self.capacity = capacity
        self.items: OrderedDict[str, float] = OrderedDict()

    def is_new(self, url: str) -> bool:
        now = time.monotonic()
        last_seen = self.items.get(url)
        self.items[url] = now
        self.items.move_to_end(url)
        while self.items and (len(self.items) > self.capacity or now - next(iter(self.items.values())) > self.ttl):
            self.items.popitem(last=False)
        return last_seen is None or now - last_seen > self.ttl


@dataclass
class StreamState:
    data: bytearray
    next_sequence: int
    updated_at: float


class TcpStreams:
    """Small in-order TCP buffer, sufficient for split HTTP headers/ClientHellos."""

    def __init__(self, timeout: float = 30.0, max_bytes: int = 65536) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.states: dict[Flow, StreamState] = {}

    def add(self, flow: Flow, sequence: int, payload: bytes) -> bytes:
        now = time.monotonic()
        if len(self.states) > 1024:
            self.states = {key: value for key, value in self.states.items() if now - value.updated_at <= self.timeout}

        state = self.states.get(flow)
        if state is None or now - state.updated_at > self.timeout or sequence > state.next_sequence:
            state = StreamState(bytearray(payload), sequence + len(payload), now)
            self.states[flow] = state
        elif sequence == state.next_sequence:
            state.data.extend(payload)
            state.next_sequence += len(payload)
            state.updated_at = now
        else:
            overlap = state.next_sequence - sequence
            if overlap < len(payload):
                state.data.extend(payload[overlap:])
                state.next_sequence += len(payload) - overlap
            state.updated_at = now

        if len(state.data) > self.max_bytes:
            state.data = bytearray(payload[-self.max_bytes :])
        return bytes(state.data)

    def clear(self, flow: Flow) -> None:
        self.states.pop(flow, None)


def default_interface_ipv4() -> str:
    """Return the IPv4 address Windows would use for the default route."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("1.1.1.1", 80))
        return probe.getsockname()[0]
    finally:
        probe.close()


def local_ipv4_addresses() -> list[str]:
    """Return every local IPv4 address that can carry outbound traffic."""
    found: set[str] = set()
    try:
        found.update(info[4][0] for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET))
    except socket.gaierror:
        pass
    try:
        found.add(default_interface_ipv4())
    except OSError:
        pass
    usable = sorted(address for address in found if not address.startswith("127."))
    if not usable:
        raise OSError("Could not determine a local IPv4 address; pass --interface ADDRESS")
    return usable


def validate_interface(address: str) -> str:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as error:
        raise ValueError("--interface must be a local IPv4 address, for example 192.168.1.20") from error
    if parsed.version != 4:
        raise ValueError("This no-install capture backend currently supports IPv4 only")
    return str(parsed)


def http_url(payload: bytes) -> str | None:
    if not payload.startswith(HTTP_METHODS):
        return None
    header_end = payload.find(b"\r\n\r\n")
    if header_end < 0:
        return None
    headers = payload[:header_end].split(b"\r\n")
    try:
        target = headers[0].split(b" ", 2)[1].decode("latin-1")
    except (IndexError, UnicodeDecodeError):
        return None
    host = next(
        (line[5:].strip().decode("latin-1") for line in headers[1:] if line.lower().startswith(b"host:")),
        None,
    )
    if target.startswith(("http://", "https://")):
        return target
    if host:
        return f"http://{host}{target if target.startswith('/') else '/' + target}"
    return None


def tls_sni(data: bytes) -> str | None:
    """Extract SNI from a TLS ClientHello record."""
    try:
        if len(data) < 9 or data[0] != 0x16 or data[5] != 0x01:
            return None
        record_end = 5 + int.from_bytes(data[3:5], "big")
        if len(data) < record_end:
            return None
        pos = 5 + 4 + 2 + 32  # record header, handshake header, client version, random
        pos += 1 + data[pos]  # session id
        pos += 2 + int.from_bytes(data[pos : pos + 2], "big")  # cipher suites
        pos += 1 + data[pos]  # compression methods
        extensions_len = int.from_bytes(data[pos : pos + 2], "big")
        pos += 2
        end = min(pos + extensions_len, record_end)
        while pos + 4 <= end:
            extension_type = int.from_bytes(data[pos : pos + 2], "big")
            extension_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
            pos += 4
            if extension_type == 0 and pos + extension_len <= end:
                name_pos = pos + 2
                while name_pos + 3 <= pos + extension_len:
                    name_type = data[name_pos]
                    name_len = int.from_bytes(data[name_pos + 1 : name_pos + 3], "big")
                    name_pos += 3
                    if name_type == 0 and name_pos + name_len <= end:
                        return data[name_pos : name_pos + name_len].decode("idna")
                    name_pos += name_len
            pos += extension_len
    except (IndexError, UnicodeDecodeError):
        return None
    return None


def outbound_tcp(packet: bytes, local_addresses: set[str]) -> tuple[Flow, int, bytes] | None:
    """Parse an outbound TCP payload from a raw IPv4 packet."""
    if len(packet) < 40 or packet[0] >> 4 != 4:
        return None
    ip_header_length = (packet[0] & 0x0F) * 4
    if ip_header_length < 20 or len(packet) < ip_header_length + 20 or packet[9] != socket.IPPROTO_TCP:
        return None
    if int.from_bytes(packet[6:8], "big") & 0x1FFF:
        return None
    source = socket.inet_ntoa(packet[12:16])
    if source not in local_addresses:
        return None
    destination = socket.inet_ntoa(packet[16:20])
    source_port = int.from_bytes(packet[ip_header_length : ip_header_length + 2], "big")
    destination_port = int.from_bytes(packet[ip_header_length + 2 : ip_header_length + 4], "big")
    sequence = int.from_bytes(packet[ip_header_length + 4 : ip_header_length + 8], "big")
    tcp_header_length = (packet[ip_header_length + 12] >> 4) * 4
    payload_start = ip_header_length + tcp_header_length
    total_length = int.from_bytes(packet[2:4], "big") or len(packet)
    payload_end = min(total_length, len(packet))
    if tcp_header_length < 20 or payload_start >= payload_end:
        return None
    return (source, source_port, destination, destination_port), sequence, packet[payload_start:payload_end]


def open_capture(address: str) -> socket.socket:
    """Put one interface into promiscuous mode using Winsock only."""
    capture = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    try:
        capture.bind((address, 0))
        capture.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        capture.setblocking(False)
    except OSError:
        capture.close()
        raise
    return capture


def close_capture(capture: socket.socket) -> None:
    try:
        capture.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except OSError:
        pass
    capture.close()


def url_from(packet: bytes, local_addresses: set[str], streams: TcpStreams) -> str | None:
    parsed = outbound_tcp(packet, local_addresses)
    if parsed is None:
        return None
    flow, sequence, payload = parsed
    data = streams.add(flow, sequence, payload)
    url = http_url(data)
    if url is None:
        host = tls_sni(data)
        url = f"https://{host}/" if host else None
    if url is not None:
        streams.clear(flow)
    return url


def run(interfaces: list[str] | None, dedupe_seconds: float, show_time: bool) -> None:
    if sys.platform != "win32":
        raise RuntimeError("The no-install raw-socket backend is currently supported on Windows only")
    addresses = [validate_interface(address) for address in interfaces] if interfaces else local_ipv4_addresses()
    local_addresses = set(addresses)
    recent = RecentUrls(dedupe_seconds)
    streams = TcpStreams()
    selector = selectors.DefaultSelector()
    captures: list[socket.socket] = []

    for address in addresses:
        try:
            capture = open_capture(address)
        except PermissionError:
            raise
        except OSError as error:
            print(f"Skipping {address}: {error}", file=sys.stderr)
            continue
        captures.append(capture)
        selector.register(capture, selectors.EVENT_READ)

    if not captures:
        raise OSError("No interface could be captured; pass --interface ADDRESS with a local IPv4 address")

    try:
        watching = ", ".join(capture.getsockname()[0] for capture in captures)
        print(f"Watching outbound IPv4 traffic on {watching}. Press Ctrl+C to stop.", file=sys.stderr)
        print("HTTPS paths are encrypted; only the hostname can usually be shown.", file=sys.stderr)
        while True:
            for key, _ in selector.select(timeout=1.0):
                capture = key.fileobj
                while True:
                    try:
                        packet = capture.recv(65535)
                    except OSError:
                        break
                    url = url_from(packet, local_addresses, streams)
                    if url and recent.is_new(url):
                        stamp = f"{datetime.now():%H:%M:%S} " if show_time else ""
                        print(f"{stamp}{url}", flush=True)
    finally:
        selector.close()
        for capture in captures:
            close_capture(capture)


def main() -> int:
    parser = argparse.ArgumentParser(description="Print URLs detected in outbound Windows IPv4 packets.")
    parser.add_argument(
        "--interface",
        metavar="IP",
        action="append",
        help="Local IPv4 address to capture; repeat to select several (default: every local IPv4 address)",
    )
    parser.add_argument("--dedupe-seconds", type=float, default=10.0, help="Suppress duplicate URLs for this many seconds")
    parser.add_argument("--no-timestamp", dest="timestamp", action="store_false", help="Print bare URLs without a clock time")
    args = parser.parse_args()
    try:
        run(args.interface, args.dedupe_seconds, args.timestamp)
    except PermissionError:
        print("Capture permission denied. Run Git Bash or PowerShell as Administrator.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Capture failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
