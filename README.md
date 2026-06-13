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

## PathFinder integration

[PathFinder](../PathFinder) is an attack-path analysis tool that consumes the
output of common enumeration tools. one-shot-enum can turn its discovered
services into the right follow-up commands for it, in two modes — pick one.

### `--suggest`

Prints the next-step enumeration commands for each discovered service (gobuster,
ffuf, nikto, whatweb, nuclei, wpscan, enum4linux-ng, smbmap, netexec,
snmp-check, kerbrute, GetNPUsers, and more), with output flags that PathFinder's
`scan` auto-detector understands, and writes a runnable `pathfinder_recon.sh`
(plus `pathfinder_recon.ps1` for Windows post-foothold steps).

```bash
python one-shot-enum.py 10.10.10.10 --suggest
```

In the generated script:

- Live (uncommented) lines are unauthenticated recon you can run immediately.
- Commands that need credentials or a foothold (LDAP dumps, Kerberoasting,
  certipy, secretsdump, linpeas/winpeas, SharpHound) are commented-out with
  `<domain>`/`<user>`/`<pass>` placeholders to edit.
- Tools whose PathFinder parser is still on the roadmap are tagged
  `parser pending`.

Then run the script and hand the loot to PathFinder:

```bash
bash pathfinder_recon.sh
python3 -m main.pathfinder scan loot/
```

### `--run`

Runs the whole pipeline for you: executes the unauthenticated recon commands
into `loot/`, then invokes PathFinder on the results. **Skips any tool that
isn't installed** and any command whose wordlist is missing; credentialed and
post-foothold commands are never executed. Intended for the Kali/attack host
(PathFinder is located in a sibling `../PathFinder` directory).

```bash
python one-shot-enum.py 10.10.10.10 --run
python one-shot-enum.py 10.10.10.10 --run --run-threads 8   # more concurrency
```

Tools run **concurrently** in a bounded worker pool (`--run-threads`, default 4).
Because their output can't be sensibly interleaved, the terminal shows a live
status table — one row per tool with its state, elapsed time, and latest
progress line:

```
Recon [4 workers]: 3 running, 2 done, 1 skipped, 0 other
  gobuster    10.10.10.10   running   00:42  | Progress: 4120 / 87664
  ffuf        10.10.10.10   running   00:42  | :: 38200/220560 :: 900 req/s
  nuclei      10.10.10.10   running   00:41  | [info] templates 1200/5000
  whatweb     10.10.10.10   done      00:03
  nikto       10.10.10.10   done      00:38
  smbmap      10.10.10.10   skip (no tool)   --:--
```

Each tool's full output is captured to `loot/_logs/<tool>_<host>.log` so nothing
is lost and failures stay diagnosable. Lower `--run-threads 1` to go easy on a
single target; raise it for multi-host sweeps.

## Requirements

- Python 3
- `nmap` in `PATH` for normal remote scanning

Only localhost scans can run without `nmap`, using the built-in fallback mode.
