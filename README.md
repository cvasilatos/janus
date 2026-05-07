# Janus

Janus extracts simple request/response datasets from classic Ethernet `pcap` files.

It reads TCP packets with application payloads, treats packets whose destination port is the configured server port as requests, treats packets whose source port is that port as responses, and matches pairs using TCP ACK/SEQ numbers. Output rows default to the LLMPot-style fields `source_text` and `target_text`, with both payloads encoded as lowercase hex.

## Install

```bash
uv sync
```

## Usage

Write JSON Lines:

```bash
uv run janus extract capture.pcap --server-port 502 --output dataset --format jsonl
```

Write CSV:

```bash
uv run janus extract capture.pcap --server-port 502 --output dataset --format csv
```

Write both CSV and JSONL in one pass:

```bash
uv run janus extract capture.pcap --server-port 502 --output dataset --format csv --format jsonl
```

Customize the request and response field names:

```bash
uv run janus extract capture.pcap --output dataset --format csv --format jsonl --request-column request_hex --response-column response_hex
```

Control Decima logging:

```bash
uv run janus extract capture.pcap --log-level debug --log-dir logs --log-name janus
```

Logging is enabled by default. Janus uses Decima to emit colorful console logs, timestamped run logs such as `logs/janus-YYYYMMDD-HHMMSS.log`, and cumulative structured JSONL logs at `logs/janus.jsonl`. Use `--no-log` to disable log setup for a run.

The JSONL output contains one object per line:

```json
{"source_text":"000100000006010300000002","target_text":"00010000000701030400000000"}
```

The CSV output uses the same two columns:

```csv
source_text,target_text
000100000006010300000002,00010000000701030400000000
```

Janus adds the enabled format suffix to the output base path, so `--output dataset --format csv --format jsonl` writes `dataset.csv` and `dataset.jsonl`.

## CLI Completion

The repository includes a zsh completion shim at `completions/janus.zsh`. You can also print it with:

```bash
uv run janus completion
```

Completion shim:

```zsh
#compdef janus

_janus() {
  eval $(env _TYPER_COMPLETE_ARGS="${words[1,$CURRENT]}" _JANUS_COMPLETE=complete_zsh janus)
}

compdef _janus janus
```

## Limits

Janus supports classic libpcap files with Ethernet link type. It does not parse `pcapng`, reassemble fragmented IP packets, or combine multi-segment TCP streams; each dataset row is built from a single request payload and a single response payload.
