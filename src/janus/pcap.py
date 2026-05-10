from __future__ import annotations

import asyncio
import csv
import json
from contextlib import ExitStack
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

import pyshark

from janus.model.request_response_pair import RequestResponsePair
from janus.model.tcp_payload import TcpPayload

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from io import TextIOWrapper
    from pathlib import Path

    from pyshark.packet.packet import Packet

SOURCE_TEXT = "source_text"
TARGET_TEXT = "target_text"


class OutputFormat(StrEnum):
    """Dataset output formats supported by the extractor."""

    CSV = "csv"
    JSONL = "jsonl"


def iter_request_response_pairs(pcap_path: Path, server_port: int, *, protocol: str | None = None, capture_layer: str | None = None) -> Iterator[RequestResponsePair]:
    """Yield TCP request/response pairs from a pcap file.

    Requests are packets whose destination port is ``server_port``. Responses are
    packets whose source port is ``server_port``. Matching uses the same
    strategy as the LLMPot parser: a request's ACK number must equal a
    response's SEQ number.
    """
    request_packets: dict[int, TcpPayload] = {}
    response_packets: dict[int, TcpPayload] = {}

    for packet in iter_tcp_payloads(pcap_path, server_port=server_port, protocol=protocol, capture_layer=capture_layer):
        if packet.dst_port == server_port:
            request_packets[packet.ack] = packet
        elif packet.src_port == server_port:
            response_packets[packet.seq] = packet

    for ack, request in request_packets.items():
        if ack in response_packets:
            yield RequestResponsePair(request=request, response=response_packets[ack])


def iter_tcp_payloads(pcap_path: Path, *, server_port: int | None = None, protocol: str | None = None, capture_layer: str | None = None) -> Iterator[TcpPayload]:
    """Yield TCP payloads decoded by tshark from ``pcap_path``."""
    capture_options: dict[str, object] = {"use_json": True, "include_raw": True, "eventloop": event_loop()}
    if protocol is not None:
        capture_options["display_filter"] = protocol
    if server_port is not None and capture_layer is not None:
        capture_options["decode_as"] = {f"tcp.port=={server_port}": capture_layer}

    capture = pyshark.FileCapture(str(pcap_path), **capture_options)
    try:
        for packet in capture:
            payload = packet_payload(packet, protocol)
            if payload:
                yield tcp_payload(packet, payload)
    finally:
        capture.close()


def event_loop() -> asyncio.AbstractEventLoop:
    """Return the current event loop, creating one for pyshark when needed."""
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


def packet_payload(packet: Packet, protocol: str | None) -> bytes:
    """Return the raw application payload bytes from a pyshark packet."""
    if protocol == "s7comm":
        return b"".join(raw_layer_bytes(packet, layer_name) for layer_name in ("tpkt", "cotp", "s7comm"))
    if protocol is not None:
        return raw_layer_bytes(packet, protocol)
    try:
        return hex_bytes(field_value(packet.tcp.payload))
    except AttributeError:
        return b""


def raw_layer_bytes(packet: Packet, layer_name: str) -> bytes:
    """Return one pyshark raw layer as bytes."""
    try:
        raw_layer = getattr(packet, f"{layer_name}_raw")
    except AttributeError:
        return b""
    return hex_bytes(field_value(raw_layer.value))


def tcp_payload(packet: Packet, payload: bytes) -> TcpPayload:
    """Build a local TCP payload record from a pyshark packet."""
    try:
        ip_layer = packet.ip
    except AttributeError:
        ip_layer = packet.ipv6
    return TcpPayload(
        timestamp=sniff_timestamp(packet),
        src_ip=str(ip_layer.src),
        src_port=field_int(packet.tcp.srcport),
        dst_ip=str(ip_layer.dst),
        dst_port=field_int(packet.tcp.dstport),
        seq=field_int(packet.tcp.seq_raw[-1]),
        ack=field_int(packet.tcp.ack_raw[-1]),
        payload=payload,
    )


def sniff_timestamp(packet: Packet) -> float:
    """Return a packet sniff timestamp as seconds since the epoch."""
    sniff_timestamp_value = getattr(packet, "sniff_timestamp", None)
    frame_info = getattr(packet, "frame_info", None)
    time_epoch = getattr(frame_info, "time_epoch", None)
    if sniff_timestamp_value is None:
        if time_epoch is None:
            raise ValueError("packet has no sniff timestamp")
        return float(field_value(time_epoch))

    try:
        return float(sniff_timestamp_value)
    except ValueError:
        try:
            return float(field_value(time_epoch))
        except (AttributeError, ValueError):
            return iso_timestamp(str(sniff_timestamp_value))


def iso_timestamp(value: str) -> float:
    """Return an ISO-8601 packet timestamp as seconds since the epoch."""
    timestamp = value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else "")
    if "." in timestamp:
        date_part, rest = timestamp.split(".", maxsplit=1)
        timezone_index = min((index for index in (rest.find("+"), rest.find("-")) if index != -1), default=len(rest))
        timestamp = f"{date_part}.{rest[:timezone_index][:6]}{rest[timezone_index:]}"
    return datetime.fromisoformat(timestamp).timestamp()


def field_value(value: object) -> str:
    """Return a pyshark field's display value."""
    raw_value = getattr(value, "value", None)
    if raw_value is not None:
        return str(raw_value)
    return str(value)


def field_int(value: object) -> int:
    """Return a pyshark field as an integer."""
    return int(field_value(value))


def hex_bytes(value: str) -> bytes:
    """Convert a tshark hex string into bytes."""
    hex_text = value.replace(":", "").replace(" ", "")
    return bytes.fromhex(hex_text)


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
