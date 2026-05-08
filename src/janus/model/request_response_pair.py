from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from janus.model.tcp_payload import TcpPayload


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
