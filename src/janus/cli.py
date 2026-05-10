from __future__ import annotations

import logging
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from decima import CustomLogger
from speculum.models.validation_mode import ValidationMode

from janus.dataset import iter_speculum_records_from_pairs, write_speculum_result_datasets
from janus.pcap import OutputFormat, iter_request_response_pairs

DEFAULT_OUTPUT = Path("dataset")
DEFAULT_LOG_DIR = Path("logs")
DEFAULT_LOG_NAME = "janus"
DEFAULT_LOGGER_CLASS_LENGTH = 24
DEFAULT_SERVER_PORT = 502
DEFAULT_REQUEST_TYPE = "captured"
DEFAULT_SEED = 0
MIN_LOGGER_CLASS_LENGTH = 1
MIN_PORT = 1
MAX_PORT = 65_535
EXTRACTION_ERRORS = (OSError, ValueError)

app = typer.Typer(help="Extract hex TCP request/response datasets from classic pcap files.", no_args_is_help=True)


class LogLevel(StrEnum):
    """Logging levels accepted by Decima."""

    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@app.command()
def extract(  # noqa: PLR0913
    pcap: Annotated[Path, typer.Argument(exists=True, file_okay=True, dir_okay=False, readable=True, help="Input classic pcap file.")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Output dataset base path. The enabled format suffix is added automatically.")] = DEFAULT_OUTPUT,
    output_formats: Annotated[
        list[OutputFormat] | None, typer.Option("--format", "-f", case_sensitive=False, help="Output dataset format. Repeat to enable both csv and jsonl.")
    ] = None,
    request_type: Annotated[str, typer.Option("--request-type", help="Speculum request_type value for captured request records.")] = DEFAULT_REQUEST_TYPE,
    seed: Annotated[int, typer.Option("--seed", help="Starting Speculum seed value. Each captured pair increments from this value.")] = DEFAULT_SEED,
    validation_mode: Annotated[
        ValidationMode, typer.Option("--validation-mode", case_sensitive=False, help="Speculum validation_mode value for captured request/response records.")
    ] = ValidationMode.REMOTE_TARGET,
    server_port: Annotated[
        int, typer.Option("--server-port", "-p", min=MIN_PORT, max=MAX_PORT, help="TCP server port used to classify request and response direction.")
    ] = DEFAULT_SERVER_PORT,
    logging_enabled: Annotated[bool, typer.Option("--log/--no-log", help="Enable Decima console, run log, and JSONL logging.")] = True,  # noqa: FBT002
    log_level: Annotated[LogLevel, typer.Option("--log-level", case_sensitive=False, help="Minimum Decima log level.")] = LogLevel.INFO,
    log_dir: Annotated[Path, typer.Option("--log-dir", help="Directory where Decima writes log files.")] = DEFAULT_LOG_DIR,
    log_name: Annotated[str, typer.Option("--log-name", help="Base filename for Decima log files.")] = DEFAULT_LOG_NAME,
    log_class_length: Annotated[
        int, typer.Option("--log-class-length", min=MIN_LOGGER_CLASS_LENGTH, help="Logger name width used by Decima console formatting.")
    ] = DEFAULT_LOGGER_CLASS_LENGTH,
) -> None:
    """Extract Speculum ``ResultRecord`` rows from a pcap."""
    logger = configure_logging(enabled=logging_enabled, log_dir=log_dir, log_name=log_name, log_level=log_level, log_class_length=log_class_length)
    enabled_formats = output_formats or [OutputFormat.JSONL]
    log_context = {
        "pcap": str(pcap),
        "output": str(output),
        "formats": [output_format.value for output_format in enabled_formats],
        "server_port": server_port,
        "request_type": request_type,
        "seed": seed,
        "validation_mode": validation_mode.value,
    }
    logger.info("Starting pcap extraction", extra={"extra_data": log_context})

    try:
        pairs = iter_request_response_pairs(pcap, server_port)
        records = iter_speculum_records_from_pairs(pairs, request_type=request_type, seed=seed, validation_mode=validation_mode)
        counts = write_speculum_result_datasets(records, output, enabled_formats)
    except EXTRACTION_ERRORS:
        logger.exception("Pcap extraction failed", extra={"extra_data": log_context})
        raise

    logger.info(
        "Finished pcap extraction",
        extra={"extra_data": {**log_context, "outputs": {str(output_path): count for output_path, count in counts.items()}, "pairs": max(counts.values(), default=0)}},
    )
    for output_path, count in counts.items():
        typer.echo(f"Wrote {count} pairs to {output_path}")


def configure_logging(*, enabled: bool, log_dir: Path, log_name: str, log_level: LogLevel, log_class_length: int) -> logging.Logger:
    """Configure Decima logging and return the extraction logger."""
    if enabled:
        CustomLogger.setup_logging(folder=str(log_dir), filename=log_name, level=log_level.value, class_length=log_class_length)
    return logging.getLogger("janus.extract")
