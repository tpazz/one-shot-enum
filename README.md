# one-shot-enum

`one-shot-enum.py` is a lightweight wrapper around `nmap` for quick first-pass pentest enumeration. It expands common target formats, finds open TCP ports, runs targeted service enumeration, and prints a clean per-host summary.

It is designed to be fast and effective: it uses multithreaded target scanning and quick initial TCP port sweeps to identify exposed services first, then drills into detailed enumeration only on the ports that are actually open.

## How it works

The tool runs in two main TCP stages:

1. Host and TCP port discovery with `nmap -Pn -p- --open`, or with the ports supplied via `--ports`.
2. Targeted service enumeration with `nmap -sC -sV` against only the open TCP ports.

It can also run a UDP top-ports scan, save raw XML and summaries, and perform optional LLM/API endpoint checks against HTTP-like services. If `nmap` is not installed, localhost-only scans can fall back to a pure-Python TCP/service probe.

This staged approach keeps broad scans quick while avoiding wasted service enumeration against closed ports.

## Usage

```bash
python one-shot-enum.py 10.10.10.5
python one-shot-enum.py 10.10.10.0/24 --threads 20
python one-shot-enum.py 10.10.10.10-20 --ports 22,80,443,8000-8010
python one-shot-enum.py localhost --llm-endpoint
python one-shot-enum.py 10.10.10.5 --llm-full --hello --save
```

Supported targets:

- Single IPv4 addresses, such as `10.10.10.5`
- CIDR ranges, such as `10.10.10.0/24`
- Short ranges, such as `10.10.10.10-20`
- Full ranges, such as `10.10.10.10-10.10.10.30`
- `localhost`

## Features

- Full TCP port discovery by default
- Optional targeted TCP scans with `--ports`
- Best-effort OS and host fingerprinting before the `-Pn` scan path
- Targeted TCP service enumeration with default scripts and version detection
- Optional UDP top-ports scanning with `--udp`
- Concurrent stage-1 scanning with `--threads`
- Live progress output from `nmap`
- Optional saved output with `--save`, including per-host reports, XML, and a CSV summary
- Colorized terminal output, disabled with `--no-color`
- Localhost fallback mode when `nmap` is unavailable

## LLM/API enumeration

Use `--llm-endpoint` to detect LLM/API-like HTTP services and output only discovered OpenAPI endpoints.

Use `--llm-full` to run the fuller LLM/API enumeration. This includes OpenAPI endpoint listing plus probes for common documentation, model, chat, health, metrics, config, and related paths.

Use `--hello` with `--llm-full` to send a small test prompt to a discovered `/chat` endpoint. `--hello` also enables `--llm-full` when used by itself.

## Output

By default, results are printed to the terminal only. With `--save`, results are written under `scan_results/` unless changed with `--outdir`.

Saved output includes:

- Per-host scan XML
- Per-host `summary.txt`
- Top-level `services_summary.csv`

## Requirements

- Python 3
- `nmap` in `PATH` for normal remote scanning

Only localhost scans can run without `nmap`, using the built-in fallback mode.
