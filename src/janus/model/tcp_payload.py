from __future__ import annotations

from dataclasses import dataclass


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
