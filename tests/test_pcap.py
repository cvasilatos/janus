from __future__ import annotations

import json
import struct
from pathlib import Path

from janus.pcap import (
    OutputFormat,
    iter_request_response_pairs,
    write_dataset,
    write_datasets,
)

CLIENT_IP = "10.0.0.10"
SERVER_IP = "10.0.0.20"
CLIENT_PORT = 12_000
SERVER_PORT = 502
REQUEST_SEQ = 100
REQUEST_ACK = 200
RESPONSE_ACK = 103
IPV4_VERSION_AND_IHL = 0x45
IPV4_HEADER_LENGTH = 20
TCP_HEADER_LENGTH = 20
TCP_DATA_OFFSET = 0x50
TCP_ACK_FLAG = 0x10
ETHERTYPE_IPV4 = b"\x08\x00"
ETHERNET_PREFIX = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
PCAP_SNAPLEN = 65_535
PCAP_LINKTYPE_ETHERNET = 1
PCAP_MAGIC_LITTLE_ENDIAN_USEC = b"\xd4\xc3\xb2\xa1"


def test_extracts_hex_request_response_pairs_from_pcap(tmp_path: Path) -> None:
    """Request and response payloads are matched by TCP ACK/SEQ numbers."""
    pcap_path = tmp_path / "capture.pcap"
    pcap_path.write_bytes(
        _pcap_bytes(
            [
                _tcp_ipv4_frame(
                    CLIENT_IP,
                    SERVER_IP,
                    CLIENT_PORT,
                    SERVER_PORT,
                    REQUEST_SEQ,
                    REQUEST_ACK,
                    b"request",
                ),
                _tcp_ipv4_frame(
                    SERVER_IP,
                    CLIENT_IP,
                    SERVER_PORT,
                    CLIENT_PORT,
                    REQUEST_ACK,
                    RESPONSE_ACK,
                    b"response",
                ),
            ],
        ),
    )

    pairs = list(iter_request_response_pairs(pcap_path, SERVER_PORT))

    assert len(pairs) == 1
    assert pairs[0].source_text == b"request".hex()
    assert pairs[0].target_text == b"response".hex()


def test_writes_jsonl_dataset(tmp_path: Path) -> None:
    """The JSONL writer emits LLMPot-style source and target text fields."""
    pcap_path = tmp_path / "capture.pcap"
    output_path = tmp_path / "dataset.jsonl"
    pcap_path.write_bytes(
        _pcap_bytes(
            [
                _tcp_ipv4_frame(
                    CLIENT_IP,
                    SERVER_IP,
                    CLIENT_PORT,
                    SERVER_PORT,
                    REQUEST_SEQ,
                    REQUEST_ACK,
                    b"aa",
                ),
                _tcp_ipv4_frame(
                    SERVER_IP,
                    CLIENT_IP,
                    SERVER_PORT,
                    CLIENT_PORT,
                    REQUEST_ACK,
                    RESPONSE_ACK,
                    b"bb",
                ),
            ],
        ),
    )

    count = write_dataset(
        iter_request_response_pairs(pcap_path, SERVER_PORT),
        output_path,
        OutputFormat.JSONL,
    )

    assert count == 1
    assert json.loads(output_path.read_text(encoding="utf-8")) == {
        "source_text": b"aa".hex(),
        "target_text": b"bb".hex(),
    }


def test_writes_multiple_formats_with_custom_columns(tmp_path: Path) -> None:
    """The multi-format writer streams pairs to CSV and JSONL with custom fields."""
    pcap_path = tmp_path / "capture.pcap"
    output_base = tmp_path / "dataset"
    pcap_path.write_bytes(
        _pcap_bytes(
            [
                _tcp_ipv4_frame(
                    CLIENT_IP,
                    SERVER_IP,
                    CLIENT_PORT,
                    SERVER_PORT,
                    REQUEST_SEQ,
                    REQUEST_ACK,
                    b"request",
                ),
                _tcp_ipv4_frame(
                    SERVER_IP,
                    CLIENT_IP,
                    SERVER_PORT,
                    CLIENT_PORT,
                    REQUEST_ACK,
                    RESPONSE_ACK,
                    b"response",
                ),
            ],
        ),
    )

    counts = write_datasets(
        iter_request_response_pairs(pcap_path, SERVER_PORT),
        output_base,
        [OutputFormat.CSV, OutputFormat.JSONL],
        "request_hex",
        "response_hex",
    )

    assert counts == {tmp_path / "dataset.csv": 1, tmp_path / "dataset.jsonl": 1}
    assert (tmp_path / "dataset.csv").read_text(
        encoding="utf-8"
    ) == f"request_hex,response_hex\n{b'request'.hex()},{b'response'.hex()}\n"
    assert json.loads((tmp_path / "dataset.jsonl").read_text(encoding="utf-8")) == {
        "request_hex": b"request".hex(),
        "response_hex": b"response".hex(),
    }


def _pcap_bytes(frames: list[bytes]) -> bytes:
    global_header = PCAP_MAGIC_LITTLE_ENDIAN_USEC + struct.pack(
        "<HHIIII",
        2,
        4,
        0,
        0,
        PCAP_SNAPLEN,
        PCAP_LINKTYPE_ETHERNET,
    )
    records = [
        struct.pack("<IIII", index, 0, len(frame), len(frame)) + frame
        for index, frame in enumerate(frames, start=1)
    ]
    return global_header + b"".join(records)


def _tcp_ipv4_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    payload: bytes,
) -> bytes:
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        TCP_DATA_OFFSET,
        TCP_ACK_FLAG,
        0,
        0,
        0,
    )
    ip_payload = tcp_header + payload
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        IPV4_VERSION_AND_IHL,
        0,
        IPV4_HEADER_LENGTH + len(ip_payload),
        0,
        0,
        64,
        6,
        0,
        _ipv4_bytes(src_ip),
        _ipv4_bytes(dst_ip),
    )
    return ETHERNET_PREFIX + ETHERTYPE_IPV4 + ip_header + ip_payload


def _ipv4_bytes(value: str) -> bytes:
    return bytes(int(part) for part in value.split("."))
