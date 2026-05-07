from __future__ import annotations

import csv
import ipaddress
import json
import struct
from collections import defaultdict, deque
from contextlib import ExitStack
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from io import TextIOWrapper
    from pathlib import Path

SOURCE_TEXT = "source_text"
TARGET_TEXT = "target_text"

DLT_EN10MB = 1
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
IPV4_VERSION = 4
IPV6_VERSION = 6
MIN_ETHERNET_HEADER_LENGTH = 14
PCAP_GLOBAL_HEADER_LENGTH = 24
MIN_IPV4_HEADER_LENGTH = 20
MIN_IPV6_HEADER_LENGTH = 40
MIN_TCP_HEADER_LENGTH = 20
TCP_PROTOCOL_NUMBER = 6
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}

FlowKey = tuple[str, int, str, int]
MatchKey = tuple[FlowKey, int]


class OutputFormat(StrEnum):
    """Dataset output formats supported by the extractor."""

    CSV = "csv"
    JSONL = "jsonl"


@dataclass(frozen=True, slots=True)
class TcpPayload:
    """A TCP segment with a non-empty application payload."""

    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    seq: int
    ack: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class RequestResponsePair:
    """A matched request and response payload pair."""

    request: TcpPayload
    response: TcpPayload

    @property
    def source_text(self) -> str:
        """Return the request payload as lowercase hexadecimal text."""
        return self.request.payload.hex()

    @property
    def target_text(self) -> str:
        """Return the response payload as lowercase hexadecimal text."""
        return self.response.payload.hex()

    def as_record(self, source_column: str, target_column: str) -> dict[str, str]:
        """Return the pair using caller-selected dataset column names."""
        return {source_column: self.source_text, target_column: self.target_text}


def iter_request_response_pairs(pcap_path: Path, server_port: int) -> Iterator[RequestResponsePair]:
    """Yield TCP request/response pairs from a classic Ethernet pcap file.

    Requests are packets whose destination port is ``server_port``. Responses are
    packets whose source port is ``server_port``. Matching uses the same
    sequence/acknowledgement strategy as the LLMPot parser: a request's ACK
    number must equal the response's SEQ number on the same TCP flow.
    """
    pending_requests: defaultdict[MatchKey, deque[TcpPayload]] = defaultdict(deque)
    pending_responses: defaultdict[MatchKey, deque[TcpPayload]] = defaultdict(deque)

    for packet in iter_tcp_payloads(pcap_path):
        if packet.dst_port == server_port:
            flow = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)
            key = (flow, packet.ack)
            if pending_responses[key]:
                yield RequestResponsePair(request=packet, response=pending_responses[key].popleft())
            else:
                pending_requests[key].append(packet)
        elif packet.src_port == server_port:
            flow = (packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port)
            key = (flow, packet.seq)
            if pending_requests[key]:
                yield RequestResponsePair(request=pending_requests[key].popleft(), response=packet)
            else:
                pending_responses[key].append(packet)


def iter_tcp_payloads(pcap_path: Path) -> Iterator[TcpPayload]:
    """Yield TCP payloads from supported packet records in ``pcap_path``."""
    for timestamp, frame in iter_ethernet_frames(pcap_path):
        packet = parse_ethernet_tcp_payload(frame, timestamp)
        if packet is not None:
            yield packet


def iter_ethernet_frames(pcap_path: Path) -> Iterator[tuple[float, bytes]]:
    """Yield timestamped Ethernet frames from a classic libpcap file."""
    with pcap_path.open("rb") as file_obj:
        header = file_obj.read(PCAP_GLOBAL_HEADER_LENGTH)
        if len(header) != PCAP_GLOBAL_HEADER_LENGTH:
            raise ValueError("pcap file is missing its global header")

        endian, timestamp_resolution = pcap_byte_order(header[:4])
        _version_major, _version_minor, _thiszone, _sigfigs, _snaplen, link_type = struct.unpack(f"{endian}HHIIII", header[4:24])
        if link_type != DLT_EN10MB:
            raise ValueError(f"unsupported pcap link type {link_type}; only Ethernet pcaps are supported")

        packet_header = struct.Struct(f"{endian}IIII")
        while record_header := file_obj.read(packet_header.size):
            if len(record_header) != packet_header.size:
                raise ValueError("pcap file has a truncated packet header")
            ts_sec, ts_fraction, included_length, _original_length = packet_header.unpack(record_header)
            frame = file_obj.read(included_length)
            if len(frame) != included_length:
                raise ValueError("pcap file has a truncated packet body")
            yield ts_sec + (ts_fraction / timestamp_resolution), frame


def pcap_byte_order(magic: bytes) -> tuple[str, int]:
    """Return struct byte order and timestamp resolution for a pcap magic value."""
    match magic:
        case b"\xd4\xc3\xb2\xa1":
            return "<", 1_000_000
        case b"\xa1\xb2\xc3\xd4":
            return ">", 1_000_000
        case b"\x4d\x3c\xb2\xa1":
            return "<", 1_000_000_000
        case b"\xa1\xb2\x3c\x4d":
            return ">", 1_000_000_000
        case _:
            raise ValueError("unsupported capture format; expected a classic pcap file, not pcapng")


def parse_ethernet_tcp_payload(frame: bytes, timestamp: float) -> TcpPayload | None:
    """Parse an Ethernet frame into a TCP payload when possible."""
    if len(frame) < MIN_ETHERNET_HEADER_LENGTH:
        return None

    offset = 12
    ether_type = int.from_bytes(frame[offset : offset + 2], "big")
    offset += 2

    while ether_type in VLAN_ETHERTYPES:
        if len(frame) < offset + 4:
            return None
        ether_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
        offset += 4

    payload = frame[offset:]
    if ether_type == ETHERTYPE_IPV4:
        return parse_ipv4_tcp_payload(payload, timestamp)
    if ether_type == ETHERTYPE_IPV6:
        return parse_ipv6_tcp_payload(payload, timestamp)
    return None


def parse_ipv4_tcp_payload(packet: bytes, timestamp: float) -> TcpPayload | None:
    """Parse an IPv4 packet into a TCP payload when possible."""
    if len(packet) < MIN_IPV4_HEADER_LENGTH:
        return None

    version = packet[0] >> 4
    header_length = (packet[0] & 0x0F) * 4
    if version != IPV4_VERSION or header_length < MIN_IPV4_HEADER_LENGTH or len(packet) < header_length:
        return None

    if packet[9] != TCP_PROTOCOL_NUMBER:
        return None

    fragment_field = int.from_bytes(packet[6:8], "big")
    fragment_offset = fragment_field & 0x1FFF
    if fragment_offset != 0:
        return None

    total_length = int.from_bytes(packet[2:4], "big")
    if total_length < header_length:
        return None

    bounded_packet = packet[: min(total_length, len(packet))]
    src_ip = str(ipaddress.IPv4Address(bounded_packet[12:16]))
    dst_ip = str(ipaddress.IPv4Address(bounded_packet[16:20]))
    return parse_tcp_segment(bounded_packet[header_length:], timestamp, src_ip, dst_ip)


def parse_ipv6_tcp_payload(packet: bytes, timestamp: float) -> TcpPayload | None:
    """Parse a simple IPv6 packet into a TCP payload when possible."""
    if len(packet) < MIN_IPV6_HEADER_LENGTH:
        return None

    version = packet[0] >> 4
    next_header = packet[6]
    if version != IPV6_VERSION or next_header != TCP_PROTOCOL_NUMBER:
        return None

    payload_length = int.from_bytes(packet[4:6], "big")
    src_ip = str(ipaddress.IPv6Address(packet[8:24]))
    dst_ip = str(ipaddress.IPv6Address(packet[24:40]))
    payload_end = min(MIN_IPV6_HEADER_LENGTH + payload_length, len(packet))
    return parse_tcp_segment(packet[MIN_IPV6_HEADER_LENGTH:payload_end], timestamp, src_ip, dst_ip)


def parse_tcp_segment(segment: bytes, timestamp: float, src_ip: str, dst_ip: str) -> TcpPayload | None:
    """Parse a TCP segment and return it only when it has application payload."""
    if len(segment) < MIN_TCP_HEADER_LENGTH:
        return None

    src_port, dst_port = struct.unpack("!HH", segment[:4])
    seq, ack = struct.unpack("!II", segment[4:12])
    header_length = (segment[12] >> 4) * 4
    if header_length < MIN_TCP_HEADER_LENGTH or len(segment) < header_length:
        return None

    payload = segment[header_length:]
    if not payload:
        return None

    return TcpPayload(timestamp=timestamp, src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port, seq=seq, ack=ack, payload=payload)


def write_dataset(pairs: Iterable[RequestResponsePair], output_path: Path, output_format: OutputFormat) -> int:
    """Write request/response pairs to ``output_path`` and return the row count."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_format is OutputFormat.CSV:
        return write_csv_dataset(pairs, output_path, SOURCE_TEXT, TARGET_TEXT)
    return write_jsonl_dataset(pairs, output_path, SOURCE_TEXT, TARGET_TEXT)


def write_datasets(pairs: Iterable[RequestResponsePair], output_base_path: Path, output_formats: Iterable[OutputFormat], source_column: str, target_column: str) -> dict[Path, int]:
    """Write request/response pairs to every requested format in one pass."""
    formats = tuple(dict.fromkeys(output_formats))
    if not formats:
        raise ValueError("at least one output format must be enabled")

    output_paths = {output_format: output_path_for_format(output_base_path, output_format) for output_format in formats}
    for output_path in output_paths.values():
        output_path.parent.mkdir(parents=True, exist_ok=True)

    counts = dict.fromkeys(output_paths.values(), 0)
    with ExitStack() as stack:
        csv_writers: dict[OutputFormat, csv.DictWriter[str]] = {}
        jsonl_files: dict[OutputFormat, TextIOWrapper] = {}
        for output_format, output_path in output_paths.items():
            if output_format is OutputFormat.CSV:
                csv_file = stack.enter_context(output_path.open("w", encoding="utf-8", newline=""))
                writer = csv.DictWriter(csv_file, fieldnames=[source_column, target_column])
                writer.writeheader()
                csv_writers[output_format] = writer
            else:
                jsonl_files[output_format] = stack.enter_context(output_path.open("w", encoding="utf-8"))

        for pair in pairs:
            record = pair.as_record(source_column, target_column)
            for output_format, output_path in output_paths.items():
                if output_format is OutputFormat.CSV:
                    csv_writers[output_format].writerow(record)
                else:
                    jsonl_files[output_format].write(f"{json.dumps(record, separators=(',', ':'))}\n")
                counts[output_path] += 1

    return counts


def output_path_for_format(output_base_path: Path, output_format: OutputFormat) -> Path:
    """Return the concrete output path for ``output_format``."""
    return output_base_path.with_suffix(f".{output_format.value}")


def write_csv_dataset(pairs: Iterable[RequestResponsePair], output_path: Path, source_column: str, target_column: str) -> int:
    """Write request/response pairs in CSV format."""
    count = 0
    with output_path.open("w", encoding="utf-8", newline="") as file_obj:
        writer = csv.DictWriter(file_obj, fieldnames=[source_column, target_column])
        writer.writeheader()
        for pair in pairs:
            writer.writerow(pair.as_record(source_column, target_column))
            count += 1
    return count


def write_jsonl_dataset(pairs: Iterable[RequestResponsePair], output_path: Path, source_column: str, target_column: str) -> int:
    """Write request/response pairs in JSON Lines format."""
    count = 0
    with output_path.open("w", encoding="utf-8") as file_obj:
        for pair in pairs:
            record = pair.as_record(source_column, target_column)
            file_obj.write(f"{json.dumps(record, separators=(',', ':'))}\n")
            count += 1
    return count
