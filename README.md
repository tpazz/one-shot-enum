# one-shot-enum

Fast first-pass enumeration around Nmap, with bounded target expansion,
service fingerprinting, read-only AI surface checks, and optional PathFinder
handoff.

## Install and verify

### Supported environment

- Python 3.11, 3.12, or 3.13
- Kali Linux or another Linux distribution is recommended for the complete
  reconnaissance workflow
- Windows is tested for the Python core, but many optional security tools and
  generated shell commands are Linux-oriented

Only scan systems you own or have explicit permission to test. An isolated lab
is the safest way to evaluate the integrated workflow.

### Basic one-shot-enum installation

Basic remote scans require Python 3, Git, and Nmap. SecLists supplies the default
wordlists used by follow-up web and username enumeration.

```bash
git clone https://github.com/tpazz/one-shot-enum.git
cd one-shot-enum

sudo apt update
sudo apt install -y nmap seclists

python3 one-shot-enum.py --help
```

The script has no mandatory third-party Python packages. A basic scan can now be
run with:

```bash
python3 one-shot-enum.py 10.10.10.5
```

### PathFinder integration

Clone both repositories into the same parent directory. PathFinder's Python
dependency must be installed before using `--pathfinder`:

```bash
mkdir pathfinder-toolkit
cd pathfinder-toolkit

git clone https://github.com/tpazz/one-shot-enum.git
git clone https://github.com/tpazz/PathFinder.git

python3 -m venv PathFinder/.venv
source PathFinder/.venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r PathFinder/requirements.txt

cd one-shot-enum
python one-shot-enum.py --help
```

The expected layout is:

```text
pathfinder-toolkit/
  one-shot-enum/
  PathFinder/
```

`--pathfinder-suggest` only generates follow-up commands. `--pathfinder` runs
the compatible tools currently installed, saves their output beneath `loot/`,
and launches the sibling PathFinder checkout. Missing optional tools are
reported and skipped, so the workflow still completes with reduced coverage.

### Optional reconnaissance tools

Install the tools relevant to the services you expect to assess. one-shot-enum
checks for these binaries before attempting to run them:

| Coverage | Tools used when available |
| --- | --- |
| Web | `curl`, `whatweb`, `ffuf`, `nikto` |
| SMB and Active Directory | `enum4linux-ng`, `smbmap`, NetExec (`nxc` or `netexec`) |
| DNS | `dig` (commonly supplied by `dnsutils`) |
| NFS | `showmount` (commonly supplied by `nfs-common`) |
| SNMP | `snmp-check` |
| Other services | `redis-cli`, `rsync`, `smtp-user-enum` |
| `--power` additions | `nuclei`, plus SecLists-backed recursive and virtual-host discovery |

Package availability and names differ between distributions. Install optional
tools from your distribution or their upstream projects, then verify them with
`command -v`, for example:

```bash
command -v nmap ffuf whatweb nikto enum4linux-ng smbmap dig showmount nuclei
```

Credentialed and post-foothold suggestions may also reference tools such as
Kerbrute, Certipy, WPScan, LinPEAS, and WinPEAS. These gated commands are printed
for operator review and are not automatically executed.

### Integrated smoke test

Run this only against an authorised lab target:

```bash
python one-shot-enum.py 192.168.56.10 \
  --pathfinder --offline --top 5 --report engagement.html
```

A successful run prints a service summary, stores per-host artifacts under
`loot/`, launches PathFinder, prints prioritised next steps, and creates the HTML
report. Add `--power` only after the base workflow succeeds.

## Quick Start

```bash
python one-shot-enum.py 10.10.10.5
python one-shot-enum.py 10.10.10.0/24 --threads 20
python one-shot-enum.py 10.10.10.10-20 --ports 22,80,443,8000-8010
python one-shot-enum.py 10.10.10.5 --pathfinder
python one-shot-enum.py 10.10.10.5 --pathfinder-suggest
```

Target formats:

- IPv4, CIDR, short/full ranges, and `localhost`
- Up to 65,536 unique expanded addresses

## Workflow

1. Runs TCP discovery with `nmap -Pn -p- --open` unless `--ports` is supplied.
2. Runs `nmap -sC -sV` only against discovered ports.
3. Checks HTTP-like services for AI, model, RAG, MCP, and agent surfaces.
4. Optionally saves scan data, runs recon, and launches PathFinder.

AI TLS defaults to `--ai-tls auto`: verify first, retry certificate failures
unverified, and label the result. Use `verify` or `insecure` to force a policy.
`--llm-endpoint` limits AI checks to a quick OpenAPI-style peek.

## PathFinder Modes

`--pathfinder-suggest` writes and prints follow-up commands:

```bash
python one-shot-enum.py 10.10.10.10 --pathfinder-suggest
```

`--pathfinder` runs available unauthenticated recon into `loot/`, then launches
a sibling `../PathFinder` checkout:

```bash
python one-shot-enum.py 10.10.10.10 --pathfinder
python one-shot-enum.py 10.10.10.10 --pathfinder --power
python one-shot-enum.py 10.10.10.0/24 --pathfinder --top 10
python one-shot-enum.py 10.10.10.0/24 --pathfinder --min-likelihood medium
python one-shot-enum.py 10.10.10.0/24 --pathfinder --offline
python one-shot-enum.py 10.10.10.0/24 --pathfinder --report engagement.html
```

PathFinder triage, filtering, enrichment, credential validation, and report
flags are passed through; run `python one-shot-enum.py --help` for the full
list. HTML reports retain evidence and commands by default, so use
`--report-redact-secrets` for a sanitized copy.

Live runs write exact command/output provenance to
`loot/_pathfinder_provenance.json`.

## Defaults

- Loot directory: `loot/`
- Findings: `findings.json` next to the loot directory
- Recon concurrency: 2 jobs per host
- Idle/scan timeouts: 180/1800 seconds
- HTTP response cap: 1 MiB
- Redirects: same scheme, host, and port only
- `--power`: nuclei, generic OpenAPI inventory, ffuf redirect-only recursion
  (depth 2, 20 req/s, 180-second total cap), and bounded vhost discovery for
  inferred DNS zones
- DNS services: bounded reverse, record, and AXFR queries for inferred zones
- Missing optional tools and wordlists are skipped

Per-tool logs are stored under `loot/_logs/`.

## Output Example

```text
[+] Targets queued: 1
[*] Scan engine: nmap
[*] Stage-1 threads: 10
[*] Stage-1 timing: T4
[*] Host fingerprint: best effort OS detection on top 20 ports before -Pn fallback
[*] Stage-1 TCP port scope: full port range
[*] Service enum timing: T3
[*] AI enumeration mode: full rich probes + read-only MCP/A2A confirmation

[+] Starting TCP full-port discovery scans...
[+] 10.10.10.10: open TCP ports -> 22,80,445,8000

[1/1] 10.10.10.10
Host: 10.10.10.10

TCP Services
  22/tcp    ssh             OpenSSH 8.9p1
  80/tcp    http            Apache httpd 2.4.49
  445/tcp   microsoft-ds    Samba smbd
  8000/tcp  http            FastAPI

AI attack pathfinder
  http://10.10.10.10:8000
    Surface: OpenAI-compatible API (high)
    Agent role: Knowledge Base / RAG agent
    Architecture: rag
    Capabilities: tool-calling, database, file-processing
    Next: review OpenAPI schema, model routes, upload paths, and tool manifests.

[+] AI surfaces -> loot/10.10.10.10/llm_enum_8000.json

Recon [1 host lane(s), 2/host]: 2 running, 5 done, 0 skipped, 0 other
> ffuf        10.10.10.10   running   00:42  | :: 38200/220560 :: 900 req/s
> nikto       10.10.10.10   running   00:41  | + Server leaks inodes via ETags
  whatweb     10.10.10.10   done      00:03
  enum4linux  10.10.10.10   done      00:18

[+] Recon complete: 7 ran clean, 0 skipped, 0 non-zero exit, 0 failed, 0 timed out, 0 interrupted
[+] Per-tool logs: loot/_logs
[+] Discovery provenance: loot/_pathfinder_provenance.json
[*] Launching PathFinder on /home/kali/labs/loot (findings -> /home/kali/labs/findings.json)
```

## Notes

- `--save` writes scan data under `scan_results/`.
- `--udp` adds a top-ports UDP scan.
- Use a fresh `--loot-dir` per engagement.
- Only localhost scans can run without Nmap, using the built-in Python fallback.

## Ethics

Use one-shot-enum only on systems you own or have explicit written permission to
test. You are responsible for how you use the output.
