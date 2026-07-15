# one-shot-enum

`one-shot-enum.py` is a fast first-pass enumeration wrapper around Nmap. It
expands targets, finds open ports, fingerprints services, performs read-only
AI/ML/RAG surface checks by default, and can hand the loot straight to
PathFinder.

## Quick Start

```bash
python one-shot-enum.py 10.10.10.5
python one-shot-enum.py 10.10.10.0/24 --threads 20
python one-shot-enum.py 10.10.10.10-20 --ports 22,80,443,8000-8010
python one-shot-enum.py 10.10.10.5 --pathfinder
python one-shot-enum.py 10.10.10.5 --pathfinder-suggest
```

Target formats:

- Single IPv4: `10.10.10.5`
- CIDR: `10.10.10.0/24`
- Short range: `10.10.10.10-20`
- Full range: `10.10.10.10-10.10.10.30`
- `localhost`

Target expansion is capped at 65,536 unique addresses. Larger CIDRs/ranges,
including broad IPv6 networks, are rejected before address materialization.

## What It Does

1. Runs TCP discovery with `nmap -Pn -p- --open` unless `--ports` is supplied.
2. Runs targeted service enum with `nmap -sC -sV` against open ports only.
3. Runs full read-only AI/ML/RAG enumeration on HTTP-like services by default.
4. Optionally writes loot and launches PathFinder.

Use `--llm-endpoint` when you only want the older quick OpenAPI-style peek. That
mode skips rich path probing, active MCP/A2A confirmation, and AI loot handoff.

## PathFinder Modes

`--pathfinder-suggest` prints follow-up commands and writes runnable recon
scripts:

```bash
python one-shot-enum.py 10.10.10.10 --pathfinder-suggest
```

`--pathfinder` runs unauthenticated recon tools into `loot/`, then launches the
sibling `../PathFinder` checkout:

```bash
python one-shot-enum.py 10.10.10.10 --pathfinder
python one-shot-enum.py 10.10.10.10 --pathfinder --power
python one-shot-enum.py 10.10.10.0/24 --pathfinder --top 10
python one-shot-enum.py 10.10.10.0/24 --pathfinder --min-likelihood medium
python one-shot-enum.py 10.10.10.0/24 --pathfinder --offline
python one-shot-enum.py 10.10.10.0/24 --pathfinder --report engagement.html
```

For each discovered web service, the default recon plan also saves the landing
page with `curl`. PathFinder extracts potential identities such as `ts_svc` as
manual-triage `username_candidate` findings; it does not promote them to valid
usernames automatically. ffuf also stores matched response bodies, allowing
PathFinder to extract candidates from discovered pages such as `/dashboard`
without requesting them a second time.

PathFinder pass-through flags supported by one-shot-enum:

- `--target-host`
- `-o` / `--output-json`
- `-v` / `-vv`
- `--max-vulns`
- `--offline`
- `--skip-github`
- `--skip-searchsploit`
- `--github-cache`
- `--no-color`
- `--oscp`
- `--top`
- `--min-likelihood`
- `--show-all`
- `--hide-discovery`
- `--hide-findings`
- `--validate-credentials`
- `--report [HTML]`
- `--report-redact-secrets`

`--target-host` is rarely needed because one-shot-enum writes a per-host loot
layout that PathFinder can attribute automatically.

Live runs also write `loot/_pathfinder_provenance.json`. After recon completes,
it records the exact tool, command, parser, output file, and completion state for
each job that created or changed loot. Skipped/failed jobs that leave an older
file untouched cannot overwrite its prior provenance. AI loot embeds the full
one-shot-enum invocation directly. PathFinder preserves every command verbatim,
including credentials supplied by the operator.

HTML reports are self-contained and offline. PathFinder preserves findings,
evidence, and producer commands by default; use `--report-redact-secrets` to
create a sanitized copy. Treat the default report as sensitive engagement loot.

Post-foothold SharpHound output can remain zipped: PathFinder detects timestamped
`*_users.json`/`*_domains.json` collections inside the archive and selects the
newest export. Pypykatz or lsassy JSON can also be dropped beneath the relevant
per-host loot directory; PathFinder separates cleartext password reuse, valid NT
pass-the-hash material, and crack-first NetNTLMv2/Kerberos/DCC2/DPAPI material.
Those owned identities are correlated only with direct SharpHound ACL and
delegation edges; PathFinder surfaces zero-hop wins and one direct high-value
target hint without performing transitive BloodHound traversal.

## Defaults

- Loot directory: `loot/`
- Findings JSON: `findings.json` next to the loot directory
- Web wordlist: `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
- User wordlist: `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`
- Per-host recon concurrency: 2 tools
- Tool idle timeout: `--run-timeout 180`
- Nmap timeout: `--scan-timeout 1800`
- AI probe response cap: 1 MiB; cross-host, cross-port, and cross-scheme redirects are blocked
- AI TLS policy: `--ai-tls auto` verifies first, then retries certificate failures unverified and labels the result; use `verify` or `insecure` to force either behavior
- Default web tools: WhatWeb, ffuf, Nikto, plus WPScan only when WordPress is detected
- `--power`: adds nuclei
- SQLMap: never fired automatically; PathFinder can parse SQLMap logs you provide

If a recon tool or wordlist is missing, `--pathfinder` skips that task and keeps
going. Full per-tool logs are written under `loot/_logs/`, and command provenance
is written to `loot/_pathfinder_provenance.json`.

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

## Full Tooling on Kali

```bash
sudo apt update
sudo apt install -y \
  nmap seclists ffuf nikto whatweb wpscan nuclei \
  enum4linux-ng smbmap netexec impacket-scripts \
  snmpcheck nfs-common redis-tools rsync smtp-user-enum kerbrute
```

PathFinder should live beside this repo:

```text
Github/
  one-shot-enum/
  PathFinder/
```

Install PathFinder dependencies from that checkout:

```bash
python3 -m pip install -r ../PathFinder/requirements.txt
```

## Notes

- `--save` writes scan XML, host summaries, and `services_summary.csv` under
  `scan_results/`.
- `--udp` adds a top-ports UDP scan.
- `--loot-dir <dir>` isolates engagements and avoids stale PathFinder input.
- Only localhost scans can run without Nmap, using the built-in Python fallback.

## Ethics

Use one-shot-enum only on systems you own or have explicit written permission to
test. You are responsible for how you use the output.
