from __future__ import annotations

import csv
import json
from contextlib import ExitStack
from dataclasses import fields
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from speculum.models.result_record import ResultRecord

from janus.pcap import OutputFormat, output_path_for_format

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator
    from io import TextIOWrapper
    from pathlib import Path

    from speculum.models.validation_mode import ValidationMode

    from janus.model.request_response_pair import RequestResponsePair


def iter_speculum_records_from_pairs(pairs: Iterable[RequestResponsePair], *, request_type: str, seed: int, validation_mode: ValidationMode) -> Iterator[ResultRecord]:
    """Yield Speculum ``ResultRecord`` rows from extracted PCAP pairs."""
    for offset, pair in enumerate(pairs):
        yield ResultRecord(
            request=pair.source_text,
            timestamp=datetime.fromtimestamp(pair.request.timestamp, UTC).isoformat(),
            request_type=request_type,
            seed=seed + offset,
            request_valid=True,
            validation_mode=validation_mode,
            response=pair.target_text,
            reply_valid=True,
        )


def load_speculum_result_record(line: str, input_path: Path, line_number: int) -> ResultRecord:
    """Load one Speculum ``ResultRecord`` from a JSONL row."""
    try:
        raw_record = json.loads(line)
        return ResultRecord.from_json_dict(raw_record)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"invalid Speculum result record at {input_path}:{line_number}") from exc


def write_speculum_result_datasets(records: Iterable[ResultRecord], output_base_path: Path, output_formats: Iterable[OutputFormat]) -> dict[Path, int]:
    """Write Speculum ``ResultRecord`` rows to every requested dataset format."""
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
                fieldnames = [field.name for field in fields(ResultRecord)]
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                csv_writers[output_format] = writer
            else:
                jsonl_files[output_format] = stack.enter_context(output_path.open("w", encoding="utf-8"))

        for record in records:
            row = record.to_json_dict()
            for output_format, output_path in output_paths.items():
                if output_format is OutputFormat.CSV:
                    csv_writers[output_format].writerow(row)
                else:
                    jsonl_files[output_format].write(f"{json.dumps(row, separators=(',', ':'))}\n")
                counts[output_path] += 1

    return counts
