#!/usr/bin/env python3
"""
nmap_wrapper.py

Lightweight nmap wrapper for one-shot initial pentest enumeration.

Features:
- Accepts:
    - single IPs:         10.10.10.5
    - CIDRs:              10.10.10.0/24
    - short ranges:       10.10.10.10-20
    - full ranges:        10.10.10.10-10.10.10.30
    - localhost:          localhost
- Stage 1:
    - Fast TCP full-port discovery scan (-Pn -T<1-5> -p- --open)
    - Optional TCP targeted discovery on user-specified ports/ranges via --ports
- Best-effort host discovery / OS fingerprint:
    - Attempts lightweight OS detection first; if unavailable, scanning continues with -Pn
- Stage 2:
    - Targeted TCP service scan (-Pn -T3 -sC -sV) on discovered open ports
- Optional UDP:
    - UDP top-ports scan (-Pn -T3 -sU --top-ports N)
- LLM/AI enum:
    - By default, probe all HTTP-like services for AI/ML/RAG fingerprints and
      actively confirm MCP/A2A metadata read-only
    - With --llm-endpoint, quick read-only peek: list OpenAPI endpoints on
      LLM/API-like services only
- Local fallback:
    - If nmap is missing, localhost scans fall back to pure-Python TCP/service checks
- Output:
    - Always prints clean terminal summaries
    - Optional per-host folders/XML/reports/CSV via --save
- Threaded host scanning for faster initial enumeration
- Live progress display:
    - periodic nmap stats
    - running discovered open-port count during discovery
"""

import argparse
import csv
import ipaddress
import json
import os
import platform
import queue
import re
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


Service = Dict[str, Any]


# =========================
# Terminal formatting
# =========================

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    # Bright palette to match PathFinder's styling.
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREY = "\033[90m"


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM") not in (None, "dumb")


USE_COLOR = supports_color()


def set_color_mode(enabled: bool) -> None:
    global USE_COLOR
    USE_COLOR = enabled


def color(text: str, code: str) -> str:
    if not USE_COLOR:
        return text
    return f"{code}{text}{C.RESET}"


def bold(text: str, code: str = "") -> str:
    """Bold (optionally coloured) text - for section headers and emphasis."""
    return color(text, C.BOLD + code)


def info(msg: str) -> None:
    print(f"{color('[*]', C.BOLD + C.CYAN)} {msg}")


def good(msg: str) -> None:
    print(f"{color('[+]', C.BOLD + C.GREEN)} {msg}")


def warn(msg: str) -> None:
    print(f"{color('[!]', C.BOLD + C.YELLOW)} {msg}")


def err(msg: str) -> None:
    print(f"{color('[-]', C.BOLD + C.RED)} {msg}", file=sys.stderr)


def progress(msg: str) -> None:
    tag = color("[>]", C.BOLD + C.CYAN)
    if sys.stdout.isatty():
        print(f"\r{tag} {msg:<120}", end="", flush=True)
    else:
        print(f"{tag} {msg}")


def clear_progress_line() -> None:
    if sys.stdout.isatty():
        print("\r" + " " * 140 + "\r", end="", flush=True)


# =========================
# Helpers
# =========================

OPEN_PORT_RE = re.compile(r"Discovered open port (\d+)/(tcp|udp) on (\S+)")
STATS_RE = re.compile(r"Stats:\s*(.*)")
PERCENT_RE = re.compile(r"About\s+([0-9.]+)%\s+done", re.IGNORECASE)
HOST_FINGERPRINT_TOP_PORTS = 20
LOCALHOST_TARGETS = {"localhost", "127.0.0.1", "::1"}
LOCALHOST_CONNECT_TIMEOUT = 0.25
LOCALHOST_READ_TIMEOUT = 0.4
LOCALHOST_SCAN_WORKERS = 256


def nmap_installed() -> bool:
    return shutil.which("nmap") is not None


def check_nmap_installed() -> None:
    if not nmap_installed():
        err("nmap not found in PATH.")
        sys.exit(1)


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def ip_to_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def is_localhost_target(value: str) -> bool:
    return value.strip().lower() in LOCALHOST_TARGETS


def target_sort_key(target: str) -> Tuple[int, int, str]:
    try:
        return (0, ip_to_int(target), target)
    except ValueError:
        if is_localhost_target(target):
            return (1, 0, target.lower())
        return (2, 0, target.lower())


def target_matches(found_target: str, requested_target: str) -> bool:
    found = found_target.strip().lower()
    requested = requested_target.strip().lower()

    if found == requested:
        return True

    if is_localhost_target(requested):
        return found in LOCALHOST_TARGETS

    return False


def expand_target(target: str) -> List[str]:
    target = target.strip()

    if is_localhost_target(target):
        return ["localhost"]

    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR '{target}': {exc}") from exc

    if "-" in target:
        left, right = target.split("-", 1)
        left = left.strip()
        right = right.strip()

        if "." in left and "." not in right:
            try:
                start_ip = ipaddress.IPv4Address(left)
                start_parts = left.split(".")
                end_octet = int(right)
                if not (0 <= end_octet <= 255):
                    raise ValueError("End octet must be between 0 and 255")
                end_parts = start_parts[:3] + [str(end_octet)]
                end_ip = ipaddress.IPv4Address(".".join(end_parts))
            except ValueError as exc:
                raise ValueError(f"Invalid short range '{target}': {exc}") from exc
        else:
            try:
                start_ip = ipaddress.IPv4Address(left)
                end_ip = ipaddress.IPv4Address(right)
            except ValueError as exc:
                raise ValueError(f"Invalid range '{target}': {exc}") from exc

        start_int = int(start_ip)
        end_int = int(end_ip)
        if end_int < start_int:
            raise ValueError(f"Invalid range '{target}': end is before start")

        return [int_to_ip(i) for i in range(start_int, end_int + 1)]

    try:
        ipaddress.IPv4Address(target)
        return [target]
    except ValueError as exc:
        raise ValueError(f"Invalid IP '{target}': {exc}") from exc


def normalize_targets(raw_targets: List[str]) -> List[str]:
    expanded: Set[str] = set()
    for raw in raw_targets:
        for ip in expand_target(raw):
            expanded.add(ip)
    return sorted(expanded, key=target_sort_key)


def parse_port_spec(port_spec: str) -> List[int]:
    ports: Set[int] = set()

    for raw_item in port_spec.split(","):
        item = raw_item.strip()
        if not item:
            continue

        if "-" in item:
            left, right = item.split("-", 1)
            try:
                start = int(left.strip())
                end = int(right.strip())
            except ValueError as exc:
                raise ValueError(f"Invalid port range '{item}'") from exc

            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Port range '{item}' must be between 1 and 65535")
            if end < start:
                raise ValueError(f"Invalid port range '{item}': end is before start")

            for port in range(start, end + 1):
                ports.add(port)
            continue

        try:
            port = int(item)
        except ValueError as exc:
            raise ValueError(f"Invalid port '{item}'") from exc

        if not (1 <= port <= 65535):
            raise ValueError(f"Port '{item}' must be between 1 and 65535")

        ports.add(port)

    if not ports:
        raise ValueError("No valid ports supplied in --ports")

    return sorted(ports)


def write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def parse_xml_file(xml_path: Path) -> ET.Element:
    try:
        return ET.parse(xml_path).getroot()
    except ET.ParseError as exc:
        raise RuntimeError(f"Failed to parse nmap XML from {xml_path}: {exc}") from exc


def merge_extra_info(*extras: Dict[str, str]) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    for extra in extras:
        for key, value in extra.items():
            if value:
                merged[key] = value
    return merged


def localhost_socket_candidates(target: str, port: int) -> List[Tuple[int, tuple]]:
    normalized = target.strip().lower()
    candidates: List[Tuple[int, tuple]] = []

    if normalized in ("localhost", "::1") and socket.has_ipv6:
        candidates.append((socket.AF_INET6, ("::1", port, 0, 0)))
    if normalized in ("localhost", "127.0.0.1"):
        candidates.append((socket.AF_INET, ("127.0.0.1", port)))
    if normalized == "::1" and not socket.has_ipv6:
        candidates = []

    return candidates


def connect_to_localhost(target: str,
                         port: int,
                         timeout: float = LOCALHOST_CONNECT_TIMEOUT) -> Optional[socket.socket]:
    for family, sockaddr in localhost_socket_candidates(target, port):
        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError:
            try:
                sock.close()
            except Exception:
                pass

    return None


def format_platform_os_guess() -> str:
    parts = [
        platform.system(),
        platform.release(),
        platform.version(),
        platform.machine(),
    ]
    return " ".join(part for part in parts if part).strip()


def localhost_service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def parse_http_server_header(response_bytes: bytes) -> Tuple[str, str]:
    text = response_bytes.decode("utf-8", errors="replace")
    match = re.search(r"^Server:\s*(.+)$", text, flags=re.IGNORECASE | re.MULTILINE)
    if not match:
        return "", ""

    server = match.group(1).strip()
    product = server.split("/")[0].strip()
    return product, server


def read_socket_banner(sock: socket.socket) -> str:
    sock.settimeout(LOCALHOST_READ_TIMEOUT)
    try:
        banner = sock.recv(512)
    except OSError:
        return ""
    return banner.decode("utf-8", errors="replace").strip()


def try_http_probe(target: str, port: int, use_ssl: bool = False) -> Optional[Dict[str, str]]:
    sock = connect_to_localhost(target, port)
    if sock is None:
        return None

    wrapped_sock: Optional[socket.socket] = sock
    try:
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            wrapped_sock = context.wrap_socket(sock, server_hostname="localhost")

        request = b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: one-shot-enum\r\n\r\n"
        wrapped_sock.settimeout(LOCALHOST_READ_TIMEOUT)
        wrapped_sock.sendall(request)
        response = wrapped_sock.recv(1024)
        if not response.startswith(b"HTTP/"):
            return None

        product, server = parse_http_server_header(response)
        return {
            "service": "https" if use_ssl else "http",
            "product": product,
            "version": "",
            "extrainfo": server,
            "tunnel": "ssl" if use_ssl else "",
            "banner": response.decode("utf-8", errors="replace").splitlines()[0].strip(),
        }
    except ssl.SSLError:
        return None
    except OSError:
        return None
    finally:
        try:
            if wrapped_sock is not None:
                wrapped_sock.close()
        except Exception:
            pass


def local_service_probe(target: str, port: int) -> Service:
    entry: Service = {
        "port": str(port),
        "protocol": "tcp",
        "service": localhost_service_name(port),
        "product": "",
        "version": "",
        "extrainfo": "",
        "tunnel": "",
        "scripts": "",
    }

    http_result = try_http_probe(target, port, use_ssl=False)
    if http_result is not None:
        entry.update(http_result)
        return entry

    https_result = try_http_probe(target, port, use_ssl=True)
    if https_result is not None:
        entry.update(https_result)
        return entry

    sock = connect_to_localhost(target, port)
    if sock is None:
        return entry

    try:
        banner = read_socket_banner(sock)
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if banner:
        entry["extrainfo"] = banner
        if banner.startswith("SSH-"):
            entry["service"] = "ssh"
            entry["product"] = banner.split("-", 2)[-1]
        elif "SMTP" in banner.upper():
            entry["service"] = entry["service"] or "smtp"
        elif "POP3" in banner.upper():
            entry["service"] = entry["service"] or "pop3"
        elif "IMAP" in banner.upper():
            entry["service"] = entry["service"] or "imap"

    return entry


def is_http_like_service(service: Service) -> bool:
    return service.get("service", "").lower() in {"http", "https"} or service.get("tunnel", "").lower() == "ssl"


# =========================
# Streaming nmap runner
# =========================

def _enqueue_pipe_lines(pipe, q: queue.Queue) -> None:
    try:
        for line in iter(pipe.readline, ''):
            q.put(line.rstrip("\n"))
    finally:
        pipe.close()


def run_nmap_with_progress(cmd: List[str], target: str, phase: str, proto: str = "tcp") -> Tuple[int, str]:
    """
    Runs nmap and streams progress to the terminal.
    Returns:
        (returncode, combined_output)
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    q: queue.Queue = queue.Queue()
    threads = [
        threading.Thread(target=_enqueue_pipe_lines, args=(proc.stdout, q), daemon=True),
        threading.Thread(target=_enqueue_pipe_lines, args=(proc.stderr, q), daemon=True),
    ]

    for t in threads:
        t.start()

    discovered_ports: Set[int] = set()
    last_stats: str = ""
    combined_lines: List[str] = []
    last_render = 0.0
    start_time = time.time()
    timed_out = False

    while proc.poll() is None or not q.empty():
        # Wall-clock ceiling: terminate a run that overruns the limit so one slow or
        # filtered host can't pin this worker forever. Only counts while nmap runs.
        if NMAP_SCAN_TIMEOUT and proc.poll() is None and (time.time() - start_time) > NMAP_SCAN_TIMEOUT:
            timed_out = True
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            break
        try:
            line = q.get(timeout=0.2)
        except queue.Empty:
            continue

        combined_lines.append(line)

        m_open = OPEN_PORT_RE.search(line)
        if m_open:
            port = int(m_open.group(1))
            found_proto = m_open.group(2)
            found_target = m_open.group(3)
            if target_matches(found_target, target) and found_proto == proto:
                discovered_ports.add(port)

        m_stats = STATS_RE.search(line)
        if m_stats:
            last_stats = m_stats.group(1).strip()

        now = time.time()
        if now - last_render >= 0.2:
            parts = [f"{phase} {target}"]
            if last_stats:
                parts.append(last_stats)
            if proto in ("tcp", "udp"):
                parts.append(f"open {proto} ports found: {len(discovered_ports)}")
            progress(" | ".join(parts))
            last_render = now

    rc = proc.wait()
    clear_progress_line()

    for t in threads:
        t.join(timeout=0.2)

    if timed_out:
        warn(f"[!] nmap {phase} on {target} exceeded the {NMAP_SCAN_TIMEOUT}s wall-clock limit; "
             f"terminated (raise or disable with --scan-timeout). This host may be skipped.")

    return rc, "\n".join(combined_lines)


# =========================
# XML parsing
# =========================

def get_host_identifier(host_el: ET.Element) -> Tuple[str, str]:
    ip_addr = "unknown"
    hostname = ""

    fallback_addr = ""
    for addr in host_el.findall("address"):
        if not fallback_addr:
            fallback_addr = addr.attrib.get("addr", "unknown")
        if addr.attrib.get("addrtype") == "ipv4":
            ip_addr = addr.attrib.get("addr", "unknown")
            break

    if ip_addr == "unknown" and fallback_addr:
        ip_addr = fallback_addr

    hostnames = host_el.find("hostnames")
    if hostnames is not None:
        first_hostname = hostnames.find("hostname")
        if first_hostname is not None:
            hostname = first_hostname.attrib.get("name", "")

    return ip_addr, hostname


def get_extra_host_info(host_el: ET.Element) -> Dict[str, str]:
    info_dict: Dict[str, str] = {}

    for addr in host_el.findall("address"):
        if addr.attrib.get("addrtype") == "mac":
            info_dict["mac"] = addr.attrib.get("addr", "")
            vendor = addr.attrib.get("vendor", "")
            if vendor:
                info_dict["vendor"] = vendor

    uptime = host_el.find("uptime")
    if uptime is not None:
        lastboot = uptime.attrib.get("lastboot", "")
        if lastboot:
            info_dict["lastboot"] = lastboot

    osmatch = host_el.find("os")
    if osmatch is not None:
        best = osmatch.find("osmatch")
        if best is not None:
            name = best.attrib.get("name", "")
            accuracy = best.attrib.get("accuracy", "")
            if name:
                info_dict["os_guess"] = f"{name} ({accuracy}%)" if accuracy else name

    return info_dict


def parse_open_ports(host_el: ET.Element, proto_filter: Optional[str] = None) -> List[int]:
    open_ports: List[int] = []
    ports_el = host_el.find("ports")
    if ports_el is None:
        return open_ports

    for port in ports_el.findall("port"):
        proto = port.attrib.get("protocol", "")
        if proto_filter and proto != proto_filter:
            continue
        state_el = port.find("state")
        if state_el is not None and state_el.attrib.get("state") == "open":
            try:
                open_ports.append(int(port.attrib["portid"]))
            except (ValueError, KeyError):
                continue

    return sorted(open_ports)


def parse_service_details(host_el: ET.Element, proto_filter: Optional[str] = None) -> List[Service]:
    services: List[Service] = []
    ports_el = host_el.find("ports")
    if ports_el is None:
        return services

    for port in ports_el.findall("port"):
        proto = port.attrib.get("protocol", "")
        if proto_filter and proto != proto_filter:
            continue

        state_el = port.find("state")
        if state_el is None or state_el.attrib.get("state") != "open":
            continue

        service_el = port.find("service")
        scripts = []
        for script in port.findall("script"):
            sid = script.attrib.get("id", "")
            out = script.attrib.get("output", "").strip()
            if sid and out:
                scripts.append(f"{sid}: {out}")

        entry = {
            "port": port.attrib.get("portid", ""),
            "protocol": proto,
            "service": "",
            "product": "",
            "version": "",
            "extrainfo": "",
            "tunnel": "",
            "scripts": "\n".join(scripts),
        }

        if service_el is not None:
            entry["service"] = service_el.attrib.get("name", "")
            entry["product"] = service_el.attrib.get("product", "")
            entry["version"] = service_el.attrib.get("version", "")
            entry["extrainfo"] = service_el.attrib.get("extrainfo", "")
            entry["tunnel"] = service_el.attrib.get("tunnel", "")

        services.append(entry)

    return sorted(services, key=lambda x: int(x["port"]) if x["port"].isdigit() else 0)


def service_banner(service: Service) -> str:
    parts = []
    if service["tunnel"]:
        parts.append(service["tunnel"])
    if service["service"]:
        parts.append(service["service"])
    if service["product"]:
        parts.append(service["product"])
    if service["version"]:
        parts.append(service["version"])
    if service["extrainfo"]:
        parts.append(f"({service['extrainfo']})")
    return " ".join(parts).strip() or "unknown"


# =========================
# LLM/API enumeration
# =========================

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
HTTP_TIMEOUT_SECONDS = 5
PROBE_TIMEOUT_SECONDS = 2
MAX_RESPONSE_CHARS = 6000
MAX_PROBE_PREVIEW_CHARS = 300
LLM_SERVICE_INDICATORS = (
    "fastapi",
    "uvicorn",
    "swagger ui",
    "openapi",
    "vcom-tunnel",
    "teradataordbms",
    "mcreport",
    "ollama",
    "openai",
    "open-webui",
    "lm studio",
    "lmstudio",
    "llama.cpp",
    "llamacpp",
    "llama",
    "llm",
    "vllm",
    "litellm",
    "langchain",
    "langserve",
    "gradio",
    "text generation inference",
    "text-generation-inference",
    "tgi",
    "kobold",
    "text-generation-webui",
    "oobabooga",
    "mistral",
    "anthropic",
    "mcp",
    "model context protocol",
    "haystack",
    "dify",
    "flowise",
    "anythingllm",
    "localai",
    "llamafile",
    "mlflow",
    "minio",
    "amazon s3",
    "amazons3",
    "bentoml",
    "bento",
    "torchserve",
    "triton inference server",
    "tritonserver",
    "tensorflow serving",
    "ray dashboard",
    "jupyter",
    "qdrant",
    "weaviate",
    "chroma",
    "chromadb",
    "milvus",
    "elasticsearch",
    "opensearch",
    "qdrant",
    "stable diffusion",
    "comfyui",
)
OPENAPI_CANDIDATE_PATHS = (
    "/openapi.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/v1/openapi.json",
    "/docs/openapi.json",
    "/swagger/v1/swagger.json",
    "/swagger.json",
)
LLM_PROBE_PATHS = (
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/ai-plugin.json",
    "/.well-known/agent.json",
    "/.well-known/agent-card.json",
    "/agent.json",
    "/agent-card.json",
    "/ai-plugin.json",
    "/agents",
    "/api/agents",
    "/a2a",
    "/threads",
    "/runs",
    "/assistants",
    "/kickoff",
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/docs",
    "/redoc",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api/docs",
    "/api/swagger",
    "/chat",
    "/chat/",
    "/v1/models",
    "/v1/model/info",
    "/v1/chat/completions",
    "/v1/responses",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/audio/transcriptions",
    "/v1/moderations",
    "/v1/rerank",
    "/v1/score",
    "/v1/tokenize",
    "/v1/detokenize",
    "/api/tags",
    "/api/version",
    "/api/ps",
    "/api/generate",
    "/api/chat",
    "/api/embeddings",
    "/api/show",
    "/info",
    "/generate",
    "/generate_stream",
    "/tokenize",
    "/detokenize",
    "/invocations",
    "/predict",
    "/predictions",
    "/models",
    "/ping",
    "/v2",
    "/v2/health/live",
    "/v2/health/ready",
    "/v2/models",
    "/api/2.0/mlflow/experiments/search",
    "/api/2.0/mlflow/registered-models/search",
    "/api/2.0/mlflow/model-versions/search",
    "/ajax-api/2.0/mlflow/experiments/search",
    "/minio/health/live",
    "/minio/health/ready",
    "/minio/health/cluster",
    "/api/status",
    "/api/sessions",
    "/api/kernels",
    "/queue/status",
    "/config",
    "/info",
    "/api/predict",
    "/run/predict",
    "/call/predict",
    "/invoke",
    "/batch",
    "/stream",
    "/input_schema",
    "/output_schema",
    "/config_schema",
    "/api/v1/prediction",
    "/api/v1/chatflows",
    "/api/v1/credentials",
    "/v1/chat-messages",
    "/v1/completion-messages",
    "/api/workspaces",
    "/api/workspace",
    "/collections",
    "/collections/",
    "/api/v1/heartbeat",
    "/api/v1/collections",
    "/v1/meta",
    "/v1/schema",
    "/v1/.well-known/ready",
    "/v1/.well-known/live",
    "/_cluster/health",
    "/_cat/indices",
    "/_aliases",
    "/sdapi/v1/sd-models",
    "/sdapi/v1/options",
    "/object_info",
    "/system_stats",
    "/mcp",
    "/mcp/",
    "/sse",
    "/messages",
    "/tools",
    "/query",
    "/ingest",
    "/upload",
    "/documents",
    "/search",
    "/workflow",
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/metrics",
    "/version",
    "/config",
    "/config.json",
)

# Endpoints that represent an LLM chat/completions interface, across common stacks
# (generic, Ollama, OpenAI-compatible, MCP-style). Used to report the chat surface.
CHAT_ENDPOINT_PATHS = (
    "/chat",
    "/api/chat",
    "/chat/completions",
    "/v1/chat/completions",
    "/v1/chat-messages",
    "/v1/messages",
    "/messages",
)


def _is_chat_endpoint(path: str) -> bool:
    return str(path).rstrip("/").lower() in CHAT_ENDPOINT_PATHS


# Agent *role* inference: what the service does, from its endpoint/route names
# (complements the framework fingerprint in AI_SURFACE_NEXT_STEPS). Substrings are
# matched against discovered paths. Order in AGENT_ROLE_PRIORITY picks the primary
# role when several capabilities are present. The capability set maps to the target
# archetypes in the AI-Red-Team notes (KB/RAG, single-agent, multi-agent/A2A,
# MCP tool server, embedding/vector store, NL-to-SQL, code-exec).
AGENT_CAPABILITY_SIGNATURES = {
    "code-execution": ("/exec", "/execute", "/run_code", "/run-code", "/eval", "/code", "/shell", "/sandbox", "/python", "/interpreter"),
    "agent-discovery": ("/.well-known/agent", "/agent.json", "/agent-card", "/agents", "/a2a"),
    "orchestration": ("/workflow", "/orchestrat", "/route", "/dispatch", "/delegate", "/supervisor",
                      "/crew", "/kickoff", "/swarm", "/handoff", "/graph", "/pipeline"),
    "mcp-tooling": ("/mcp", "/sse", "/jsonrpc", "/rpc", "/invoke", "/tools"),
    "vector-store": ("/collection", "/points", "/scroll", "/objects", "/v1/schema", "/_search", "/_cat/indices", "/upsert"),
    "knowledge-base": ("/kb", "/knowledge", "/rag", "/document", "/ingest", "/corpus", "/embed", "/retriev"),
    "tool-calling": ("/tool", "/function", "/plugin", "/action", "tool-call"),
    "database": ("/db", "/sql", "db-schema", "/table", "/datasource", "nl2sql", "text2sql", "text-to-sql"),
    "web-browsing": ("/browse", "/fetch", "/crawl", "/scrape", "/render", "/url"),
    "file-processing": ("/upload", "/summarize", "/review", "/parse", "/extract", "/ocr", "/file", "/transcri"),
    "memory": ("/memory", "/history", "/recall", "/remember", "/thread"),
    "conversational": ("/chat", "/session", "/message", "/conversation", "/completions", "/reset", "/query"),
}
AGENT_ROLE_PRIORITY = (
    ("code-execution", "Code / Execution agent"),
    ("agent-discovery", "A2A / multi-agent system"),
    ("orchestration", "Multi-agent orchestrator"),
    ("mcp-tooling", "MCP / tool server"),
    ("vector-store", "Embedding / vector store"),
    ("knowledge-base", "Knowledge Base / RAG agent"),
    ("database", "Database / NL-to-SQL agent"),
    ("web-browsing", "Web-browsing agent"),
    ("tool-calling", "Tool-using single agent"),
    ("file-processing", "Document-processing agent"),
    ("memory", "Stateful / memory agent"),
    ("conversational", "Conversational agent / chatbot"),
)
# High-level architecture (topology) derived from which capabilities are present.
# This is the "KB/RAG vs Single vs Multi vs Embedding" bucket the notes describe.
AGENT_ARCHITECTURE_RULES = (
    ("multi-agent", ("agent-discovery", "orchestration")),
    ("tool-server", ("mcp-tooling",)),
    ("vector-store", ("vector-store",)),
    ("rag", ("knowledge-base",)),
    ("single-agent", ("code-execution", "tool-calling", "web-browsing",
                      "database", "file-processing", "memory", "conversational")),
)
# Multi-agent / orchestration frameworks that leave HTTP path fingerprints
# (from A2A.md). Checked in order; the first match wins. Answer-serving frameworks
# (LangServe/Flowise/Dify) are already reported by infer_ai_surfaces.
AGENT_FRAMEWORK_SIGNATURES = (
    ("Google A2A", ("/.well-known/agent.json", "/.well-known/agent-card.json", "/a2a")),
    ("Model Context Protocol", ("/mcp", "/sse", "/jsonrpc")),
    ("LangGraph", ("/threads", "/runs", "/assistants")),
    ("CrewAI", ("/crew", "/kickoff")),
    ("OpenAI Swarm", ("/swarm", "/handoff")),
)


def infer_agent_profile(llm_enum: Dict[str, Any]) -> Dict[str, Any]:
    """Infer the agent's role, architecture, and capabilities from its route names.

    Returns {"role", "architecture", "framework", "capabilities": [...],
    "evidence": {cap: [paths]}} or {} if nothing recognisable.

    - role         fine-grained label (most security-relevant capability wins)
    - architecture topology bucket: multi-agent / tool-server / vector-store / rag /
                   single-agent / unknown (the KB/RAG-vs-Single-vs-Multi taxonomy)
    - framework    orchestration framework if a path fingerprint matches (A2A/MCP/...)

    code-execution, tool-calling, mcp-tooling and multi-agent orchestration are the
    highest-impact (agency, injection-to-action, cross-agent trust)."""
    paths = set()
    for ep in llm_enum.get("endpoints", []):
        if isinstance(ep, dict) and ep.get("path"):
            paths.add(str(ep["path"]).lower())
    for hit in llm_enum.get("probe_hits", []):
        if isinstance(hit, dict) and hit.get("path"):
            paths.add(str(hit["path"]).lower())
    if not paths:
        return {}

    evidence = {}
    for cap, signs in AGENT_CAPABILITY_SIGNATURES.items():
        matched = sorted({p for p in paths if any(s in p for s in signs)})
        if matched:
            evidence[cap] = matched[:5]
    if not evidence:
        return {}

    role = "AI agent / service"
    for cap, label in AGENT_ROLE_PRIORITY:
        if cap in evidence:
            role = label
            break

    architecture = "unknown"
    for arch, caps in AGENT_ARCHITECTURE_RULES:
        if any(cap in evidence for cap in caps):
            architecture = arch
            break

    framework = ""
    for name, signs in AGENT_FRAMEWORK_SIGNATURES:
        if any(any(s in p for p in paths) for s in signs):
            framework = name
            break

    # A recognised orchestration framework implies at least a multi-agent / tool-server
    # topology even when the generic capability routes alone didn't reveal it
    # (e.g. LangGraph's /threads,/runs,/assistants).
    if framework and architecture in ("unknown", "single-agent"):
        architecture = "tool-server" if framework == "Model Context Protocol" else "multi-agent"

    # Capabilities ordered by the same priority for stable, meaningful display.
    ordered_caps = [cap for cap, _ in AGENT_ROLE_PRIORITY if cap in evidence]
    return {
        "role": role,
        "architecture": architecture,
        "framework": framework,
        "capabilities": ordered_caps,
        "evidence": evidence,
    }


# Read-only vector-store / RAG collection enumeration. The AI-red-team "plaintext
# first" rule: an exposed, UNAUTHENTICATED vector DB usually lets you read the
# source chunks directly (no embedding inversion needed) - the highest-value RAG
# win. Each entry is (engine, GET listing path). We send no auth, so a 200 with a
# parseable listing means unauthenticated read access.
VECTOR_STORE_LISTINGS = (
    ("Qdrant", "/collections"),
    ("Chroma", "/api/v2/tenants/default_tenant/databases/default_database/collections"),
    ("Chroma", "/api/v1/collections"),
    ("Weaviate", "/v1/schema"),
    ("Elasticsearch/OpenSearch", "/_aliases"),
)


def _extract_collection_names(engine: str, payload: Any) -> Optional[List[str]]:
    """Pull collection/class/index names from a vector-store listing response.

    Returns a list (possibly empty = reachable but no collections) if the payload
    matches this engine's shape, or None if it doesn't (so we keep trying)."""
    try:
        if engine == "Qdrant":
            cols = payload.get("result", {}).get("collections")
            if isinstance(cols, list):
                return [c.get("name") for c in cols if isinstance(c, dict) and c.get("name")]
        elif engine == "Chroma":
            if isinstance(payload, list):
                return [c.get("name") for c in payload if isinstance(c, dict) and c.get("name")]
        elif engine == "Weaviate":
            classes = payload.get("classes")
            if isinstance(classes, list):
                return [c.get("class") for c in classes if isinstance(c, dict) and c.get("class")]
        elif engine == "Elasticsearch/OpenSearch":
            if isinstance(payload, dict):
                return [name for name in payload.keys() if not str(name).startswith(".")]
    except AttributeError:
        return None
    return None


def enumerate_vector_store(base_url: str) -> Dict[str, Any]:
    """Read-only: list collections/classes/indices from an exposed vector store.

    Returns {"engine","url","collections":[...],"collection_count","unauthenticated"}
    or {} if no known vector-store listing is reachable. GET-only; no writes."""
    for engine, path in VECTOR_STORE_LISTINGS:
        response = http_request(f"{base_url}{path}")
        if not response.get("ok") or response.get("json") is None:
            continue
        names = _extract_collection_names(engine, response["json"])
        if names is None:
            continue
        return {
            "engine": engine,
            "url": f"{base_url}{path}",
            "collections": [n for n in names if n][:50],
            "collection_count": len(names),
            "unauthenticated": True,
        }
    return {}


# Active (opt-in) MCP/A2A capability confirmation. This is still read-only - it
# fetches agent-discovery documents and sends the standard MCP JSON-RPC
# initialize / tools/list handshake to turn *inferred* capabilities into a
# *confirmed* tool inventory. It never invokes a tool. Categories mirror the
# AI-red-team MCP triage (fs / exec / net / db / secrets / source-control).
MCP_TOOL_CATEGORIES = {
    "filesystem-read": ("read_file", "readfile", "cat ", "filesystem", "file read", "list_dir", "read_document", "list_files"),
    "filesystem-write": ("write_file", "writefile", "edit_file", "file write", "create_file", "delete_file"),
    "code-execution": ("shell", "command", "execute", "subprocess", "terminal", "python", "run_code", "run_command", "eval", "exec"),
    "network-egress": ("fetch", "http", "url", "request", "browser", "curl", "webhook"),
    "database-read": ("select", "query", "database", "sql", "schema", "table"),
    "database-write": ("insert", "update", "delete", "drop", "execute sql", "write sql"),
    "source-control": ("git", "github", "gitlab", "repository", "commit", "snippet"),
    "secrets/identity": ("secret", "token", "credential", "identity", "vault", "password", "api_key", "rotate"),
}


def classify_mcp_tool(tool: Dict[str, Any]) -> List[str]:
    text = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
    return [category for category, terms in MCP_TOOL_CATEGORIES.items() if any(term in text for term in terms)]


def _parse_jsonrpc_body(response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the JSON-RPC object from an MCP response that may be JSON or SSE."""
    if isinstance(response.get("json"), dict):
        return response["json"]
    obj = None
    for line in (response.get("text") or "").splitlines():
        line = line.strip()
        if line.startswith("data:"):
            try:
                obj = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                continue
    return obj if isinstance(obj, dict) else None


def enumerate_mcp_tools(base_url: str, mcp_path: str = "/mcp") -> Dict[str, Any]:
    """Read-only MCP capability confirmation via JSON-RPC initialize + tools/list.

    Returns {"path","url","tools":[{name,description,categories}],"tool_count"}
    or {} if no tool list is recovered. Never invokes a tool."""
    url = f"{base_url}{mcp_path}"
    accept = {"Accept": "application/json, text/event-stream"}
    initialize = http_request(url, method="POST", extra_headers=accept, payload={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "one-shot-enum", "version": "1.0"}},
    })
    if initialize.get("status") is None or initialize.get("status") >= 500:
        return {}
    session = (initialize.get("headers") or {}).get("Mcp-Session-Id") \
        or (initialize.get("headers") or {}).get("mcp-session-id")
    list_headers = dict(accept)
    if session:
        list_headers["Mcp-Session-Id"] = session
    listing = http_request(url, method="POST", extra_headers=list_headers, payload={
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

    body = _parse_jsonrpc_body(listing)
    tools: List[Dict[str, Any]] = []
    if isinstance(body, dict):
        result = body.get("result") if isinstance(body.get("result"), dict) else body
        raw_tools = result.get("tools") if isinstance(result, dict) else None
        if isinstance(raw_tools, list):
            for tool in raw_tools:
                if isinstance(tool, dict) and tool.get("name"):
                    tools.append({
                        "name": tool.get("name"),
                        "description": tool.get("description", ""),
                        "categories": classify_mcp_tool(tool),
                    })
    if not tools:
        return {}
    return {"path": mcp_path, "url": url, "tools": tools[:50], "tool_count": len(tools)}


AGENT_CARD_PATHS = (
    "/.well-known/agent.json",
    "/.well-known/agent-card.json",
    "/agent.json",
    "/agent-card.json",
    "/agents",
    "/api/agents",
)


def fetch_agent_cards(base_url: str) -> List[Dict[str, Any]]:
    """Read-only: fetch A2A / agent-discovery documents that advertise capabilities,
    endpoints, and (crucially) whether a self-service registration route exists."""
    cards: List[Dict[str, Any]] = []
    for path in AGENT_CARD_PATHS:
        response = http_request(f"{base_url}{path}")
        if response.get("ok") and response.get("json") is not None:
            cards.append({"path": path, "card": response["json"]})
    return cards


AI_SURFACE_NEXT_STEPS = {
    "openai-compatible": [
        "GET /v1/models to list model IDs and confirm auth requirements.",
        "POST /v1/chat/completions with a harmless prompt and explicit model.",
        "Check for tool/function calling, system-prompt leakage, and weak output guardrails.",
        "If RAG endpoints also exist, move to indirect prompt injection and source extraction tests.",
    ],
    "ollama": [
        "GET /api/tags to list local models.",
        "POST /api/generate or /api/chat with a harmless capability prompt.",
        "Check whether model pull/create/delete endpoints are exposed or unauthenticated.",
        "If remote callbacks are in scope, test whether prompts can trigger tool or URL fetch behavior.",
    ],
    "vllm": [
        "GET /v1/models and /version or /metrics to confirm vLLM exposure.",
        "POST /v1/chat/completions with the discovered model ID.",
        "Probe tokenizer endpoints if exposed; compare prompt filtering before and after tokenization.",
        "Check whether LoRA adapter or served-model arguments leak through banners, docs, or metrics.",
    ],
    "tgi": [
        "GET /info to identify Text Generation Inference model metadata.",
        "POST /generate with a benign prompt and short max_new_tokens.",
        "Check /metrics for model name, queue pressure, and deployment hints.",
        "Test prompt injection and streaming output handling once generation is confirmed.",
    ],
    "gradio": [
        "GET /config and /info to recover function names, parameters, and queue behavior.",
        "POST /api/predict or /run/predict using the discovered fn_index/schema.",
        "Inspect file upload parameters for path traversal, SSRF, or unsafe processing.",
        "If a chatbot component exists, test prompt injection and history handling.",
    ],
    "langserve": [
        "GET /input_schema, /output_schema, and /config_schema to recover chain inputs.",
        "POST /invoke with the minimum valid schema.",
        "Check /stream and /batch for weaker validation than /invoke.",
        "If retriever fields exist, test query rewriting, source disclosure, and RAG poisoning paths.",
    ],
    "agent-mcp": [
        "Fetch /.well-known/agent.json or tool manifests and record capabilities.",
        "Probe /mcp, /sse, and /messages for transport, auth, and session requirements.",
        "Look for file, shell, browser, HTTP fetch, email, GitHub, or cloud tools.",
        "Test tool argument injection and confused-deputy behavior with low-impact inputs first.",
    ],
    "rag-vector": [
        "List collections/indexes and sample metadata with the lowest-impact read endpoint.",
        "Identify embedding model, chunking hints, document titles, and tenant boundaries.",
        "Test whether writes/uploads are allowed before attempting any poisoning.",
        "If readable, search chunks for prompts, secrets, source docs, and tool instructions.",
    ],
    "mlflow": [
        "List experiments, registered models, and model versions via MLflow API endpoints.",
        "Check artifact URIs for writable stores, credentials, or local filesystem paths.",
        "Identify model flavors and unsafe loaders such as pickle, pyfunc, joblib, or torch.",
        "If write access exists, follow the artifact consumer before testing model/package tampering.",
    ],
    "object-store": [
        "List buckets anonymously (read-only): aws s3 ls --no-sign-request --endpoint-url http://HOST:9000 (or mc alias set + mc ls).",
        "Recurse buckets for model artifacts (.pkl/.joblib/.pt/.bin/.h5/.onnx), .env, and credential/config files.",
        "Check for write access before anything else - a writable bucket is artifact/model tampering.",
        "If it backs MLflow, a writable artifact store is a pickle/joblib deserialization path to code execution on the model consumer.",
    ],
    "model-serving": [
        "List loaded models and versions.",
        "Check health/readiness plus metrics for model names, paths, and backend framework.",
        "Send a minimal inference request only after recovering the expected schema.",
        "Look for model repository write paths, unsafe deserialization, and shared cache directories.",
    ],
    "notebook": [
        "Check whether token auth is required for /api/status, /api/sessions, and /api/kernels.",
        "If authenticated, enumerate notebooks and kernels without executing code first.",
        "Look for exposed files, saved credentials, environment variables, and mounted project paths.",
        "Treat kernel execution as code execution and preserve evidence carefully.",
    ],
    "ai-workflow": [
        "Enumerate workflow/chatflow definitions, credentials references, and public prediction endpoints.",
        "Identify nodes that fetch URLs, call tools, run code, or access vector stores.",
        "Test unauthenticated prediction with benign inputs before prompt/tool abuse.",
        "Check exported flows for embedded API keys, database URLs, or agent prompts.",
    ],
    "image-generation": [
        "List models, samplers, nodes, or workflow object info.",
        "Check file upload/output directories and whether paths are user-controlled.",
        "Test harmless generation parameters before probing plugin or custom-node behavior.",
        "Look for model/plugin supply-chain paths and exposed filesystem mounts.",
    ],
}


def resembles_llm_service(service: Service) -> bool:
    haystack = " ".join([
        service_banner(service),
        service.get("scripts", ""),
        service.get("service", ""),
        service.get("product", ""),
        service.get("extrainfo", ""),
    ]).lower()

    return any(indicator in haystack for indicator in LLM_SERVICE_INDICATORS)


def service_base_url(target: str, service: Service) -> str:
    tunnel = service.get("tunnel", "").lower()
    name = service.get("service", "").lower()
    port = str(service.get("port", "")).strip()
    scheme = "https" if tunnel == "ssl" or name in ("https", "ssl/http") else "http"
    return f"{scheme}://{target}:{port}" if port else f"{scheme}://{target}"


def truncate_text(value: str, limit: int = MAX_RESPONSE_CHARS) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n... [truncated]"


def http_request(url: str,
                 method: str = "GET",
                 payload: Optional[Dict[str, Any]] = None,
                 timeout: int = HTTP_TIMEOUT_SECONDS,
                 extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    data = None
    headers = {
        "Accept": "application/json, text/plain;q=0.9, */*;q=0.8",
        "User-Agent": "one-shot-enum/llm-enum",
    }

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)

    request = urllib.request.Request(url, data=data, headers=headers, method=method)

    response_headers: Dict[str, str] = {}
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body_bytes = response.read()
            status = response.getcode()
            content_type = response.headers.get("Content-Type", "")
            response_headers = {k: v for k, v in response.headers.items()}
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read()
        status = exc.code
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        if exc.headers:
            response_headers = {k: v for k, v in exc.headers.items()}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "ok": False,
            "status": None,
            "content_type": "",
            "text": "",
            "json": None,
            "headers": {},
            "error": str(exc),
        }

    text = body_bytes.decode("utf-8", errors="replace")
    parsed_json = None
    try:
        parsed_json = json.loads(text)
    except json.JSONDecodeError:
        pass

    return {
        "ok": 200 <= status < 400,
        "status": status,
        "content_type": content_type,
        "text": text,
        "json": parsed_json,
        "headers": response_headers,
        "error": "",
    }



def format_probe_json_preview(response: Dict[str, Any]) -> List[str]:
    if response.get("json") is None:
        return []

    pretty_json = json.dumps(response["json"], indent=2, sort_keys=True)
    return pretty_json.splitlines()


def probe_response_preview(response: Dict[str, Any]) -> str:
    content_type = response.get("content_type", "").lower()
    text = response.get("text", "").strip()

    if response.get("json") is not None:
        preview = ""
    elif "text/html" in content_type:
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
        preview = title_match.group(1).strip() if title_match else ""
    elif "text/" in content_type or text.startswith(("Contact:", "Policy:", "{", "[")):
        preview = " ".join(text.split())
    else:
        preview = ""

    return truncate_text(preview, MAX_PROBE_PREVIEW_CHARS).replace("\n", " ")


def is_interesting_probe_response(response: Dict[str, Any]) -> bool:
    status = response.get("status")
    if status is None:
        return False
    # 400/422 catch custom FastAPI/Starlette agents that reject a GET on a
    # body-required POST route with "Bad Request"/"Unprocessable Entity" rather
    # than 404 - the route (and the surface) exists.
    return 200 <= status < 400 or status in (400, 401, 403, 405, 422)


def probe_llm_paths(base_url: str) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=8) as executor:
        future_map = {
            executor.submit(
                http_request,
                f"{base_url}{path}",
                timeout=PROBE_TIMEOUT_SECONDS,
            ): (index, path)
            for index, path in enumerate(LLM_PROBE_PATHS)
        }

        for future in as_completed(future_map):
            index, path = future_map[future]
            try:
                response = future.result()
            except Exception as exc:
                response = {
                    "ok": False,
                    "status": None,
                    "content_type": "",
                    "text": "",
                    "json": None,
                    "error": str(exc),
                }

            if not is_interesting_probe_response(response):
                continue

            hits.append({
                "index": index,
                "path": path,
                "status": response.get("status"),
                "content_type": response.get("content_type", ""),
                "preview": probe_response_preview(response),
                "json_preview_lines": format_probe_json_preview(response),
            })

    return sorted(hits, key=lambda hit: hit["index"])


def parse_openapi_endpoints(openapi_doc: Any) -> List[Dict[str, str]]:
    if not isinstance(openapi_doc, dict):
        return []

    paths = openapi_doc.get("paths", {})
    if not isinstance(paths, dict):
        return []

    endpoints: List[Dict[str, str]] = []
    for path, operations in paths.items():
        if not isinstance(operations, dict):
            continue
        for method in operations:
            method_name = str(method)
            if method_name.lower() in HTTP_METHODS:
                endpoints.append({
                    "method": method_name.upper(),
                    "path": str(path),
                })

    return endpoints


def _normalized_ai_paths(llm_enum: Dict[str, Any]) -> Set[str]:
    paths: Set[str] = set()
    for endpoint in llm_enum.get("endpoints", []):
        path = str(endpoint.get("path", "")).strip().lower().rstrip("/")
        if path:
            paths.add(path or "/")
    for hit in llm_enum.get("probe_hits", []):
        path = str(hit.get("path", "")).strip().lower().rstrip("/")
        if path:
            paths.add(path or "/")
    return paths


def _ai_preview_text(llm_enum: Dict[str, Any]) -> str:
    chunks: List[str] = []
    for hit in llm_enum.get("probe_hits", []):
        chunks.append(str(hit.get("preview", "")))
        chunks.extend(str(line) for line in hit.get("json_preview_lines", []))
    return " ".join(chunks).lower()


def _path_matches(paths: Set[str], candidates: Tuple[str, ...]) -> bool:
    wanted = tuple(candidate.lower().rstrip("/") or "/" for candidate in candidates)
    for path in paths:
        if path in wanted:
            return True
        if any(candidate.endswith("/") and path.startswith(candidate.rstrip("/")) for candidate in wanted):
            return True
    return False


def _path_contains(paths: Set[str], *needles: str) -> bool:
    return any(any(needle in path for needle in needles) for path in paths)


def _add_ai_surface(surfaces: Dict[str, Dict[str, Any]],
                    key: str,
                    label: str,
                    confidence: str,
                    evidence: List[str]) -> None:
    confidence_rank = {"low": 1, "medium": 2, "high": 3}
    existing = surfaces.get(key)
    if existing is None:
        surfaces[key] = {
            "key": key,
            "label": label,
            "confidence": confidence,
            "evidence": [],
            "next_steps": AI_SURFACE_NEXT_STEPS.get(key, []),
        }
        existing = surfaces[key]
    if confidence_rank.get(confidence, 0) > confidence_rank.get(existing["confidence"], 0):
        existing["confidence"] = confidence
    for item in evidence:
        if item and item not in existing["evidence"]:
            existing["evidence"].append(item)


def infer_ai_surfaces(service: Service, llm_enum: Dict[str, Any]) -> List[Dict[str, Any]]:
    paths = _normalized_ai_paths(llm_enum)
    preview = _ai_preview_text(llm_enum)
    banner = " ".join([
        service_banner(service),
        service.get("scripts", ""),
        service.get("service", ""),
        service.get("product", ""),
        service.get("extrainfo", ""),
    ]).lower()
    endpoints = llm_enum.get("endpoints", [])
    surfaces: Dict[str, Dict[str, Any]] = {}

    if _path_matches(paths, ("/v1/chat/completions", "/v1/completions", "/v1/responses", "/v1/embeddings")):
        _add_ai_surface(
            surfaces,
            "openai-compatible",
            "OpenAI-compatible LLM API",
            "high",
            ["OpenAI-style /v1 generation or embedding endpoint exposed"],
        )
    elif _path_matches(paths, ("/v1/models",)) and ("openai" in banner or "openai" in preview or endpoints):
        _add_ai_surface(
            surfaces,
            "openai-compatible",
            "OpenAI-compatible LLM API",
            "medium",
            ["/v1/models-style endpoint exposed"],
        )

    if "vllm" in banner or "vllm" in preview:
        _add_ai_surface(surfaces, "vllm", "vLLM OpenAI-compatible server", "high", ["vLLM marker in banner or response"])
    elif _path_matches(paths, ("/v1/tokenize", "/v1/detokenize", "/v1/score")):
        _add_ai_surface(surfaces, "vllm", "Possible vLLM server", "medium", ["vLLM-like tokenizer or score endpoint exposed"])

    if "text generation inference" in banner or "text-generation-inference" in banner or "text generation inference" in preview:
        _add_ai_surface(surfaces, "tgi", "Hugging Face Text Generation Inference", "high", ["TGI marker in banner or response"])
    elif _path_matches(paths, ("/generate", "/generate_stream")) and not _path_matches(paths, ("/api/generate",)):
        _add_ai_surface(surfaces, "tgi", "Possible text-generation inference API", "medium", ["/info or /generate endpoint exposed"])

    if _path_matches(paths, ("/api/tags", "/api/generate", "/api/chat", "/api/ps", "/api/show")):
        _add_ai_surface(surfaces, "ollama", "Ollama API", "high", ["Ollama /api/* endpoint exposed"])
    elif "ollama" in banner or "ollama" in preview:
        _add_ai_surface(surfaces, "ollama", "Ollama API", "medium", ["Ollama marker in banner or response"])

    if _path_matches(paths, ("/config", "/queue/status", "/api/predict", "/run/predict", "/call/predict")) and (
        "gradio" in banner or "gradio" in preview or _path_matches(paths, ("/queue/status",))
    ):
        _add_ai_surface(surfaces, "gradio", "Gradio app", "high", ["Gradio config, queue, or predict endpoint exposed"])

    if _path_matches(paths, ("/invoke", "/batch", "/stream", "/input_schema", "/output_schema", "/config_schema")):
        _add_ai_surface(surfaces, "langserve", "LangServe/LangChain API", "high", ["LangServe invoke/schema endpoint exposed"])
    elif "langchain" in banner or "langserve" in banner or "langchain" in preview:
        _add_ai_surface(surfaces, "langserve", "Possible LangChain/LangServe API", "medium", ["LangChain/LangServe marker in banner or response"])

    if _path_matches(paths, ("/.well-known/agent.json", "/agent.json", "/mcp", "/sse", "/messages")):
        _add_ai_surface(surfaces, "agent-mcp", "Agent/MCP surface", "high", ["Agent manifest, MCP, SSE, or messages endpoint exposed"])
    elif "model context protocol" in banner or " mcp " in f" {banner} " or "model context protocol" in preview:
        _add_ai_surface(surfaces, "agent-mcp", "Possible Agent/MCP surface", "medium", ["MCP marker in banner or response"])

    if _path_matches(paths, ("/collections", "/api/v1/collections", "/v1/meta", "/v1/schema", "/_cat/indices", "/_cluster/health")):
        _add_ai_surface(surfaces, "rag-vector", "Vector DB / RAG data store", "high", ["Vector/index collection endpoint exposed"])
    elif any(marker in banner or marker in preview for marker in ("qdrant", "chromadb", "chroma", "weaviate", "milvus", "opensearch", "elasticsearch")):
        _add_ai_surface(surfaces, "rag-vector", "Possible Vector DB / RAG data store", "medium", ["Vector-store marker in banner or response"])

    if _path_contains(paths, "mlflow") or "mlflow" in banner or "mlflow" in preview:
        _add_ai_surface(surfaces, "mlflow", "MLflow tracking/model registry", "high", ["MLflow API endpoint or marker exposed"])

    # Object store (MinIO / S3-compatible): the artifact-store sink behind MLflow/ML
    # pipelines - model artifacts, training data, and often its own credentials.
    if _path_matches(paths, ("/minio/health/live", "/minio/health/ready", "/minio/health/cluster")) or "minio" in banner or "minio" in preview:
        _add_ai_surface(surfaces, "object-store", "MinIO / S3-compatible object store", "high", ["MinIO health endpoint or marker exposed"])
    elif "listallmybucketsresult" in preview or "amazons3" in banner or "amazon s3" in banner:
        _add_ai_surface(surfaces, "object-store", "S3-compatible object store", "medium", ["S3-style API response detected"])

    if _path_matches(paths, ("/v2/models", "/v2/health/live", "/v2/health/ready")):
        _add_ai_surface(surfaces, "model-serving", "Triton-style model serving API", "medium", ["Triton-style /v2 model-serving endpoint exposed"])
    elif _path_matches(paths, ("/models", "/predictions")) and _path_matches(paths, ("/ping", "/invocations", "/predict")):
        _add_ai_surface(surfaces, "model-serving", "Generic model serving API", "medium", ["Model listing plus prediction/health endpoint exposed"])
    if any(marker in banner or marker in preview for marker in ("torchserve", "triton", "tensorflow serving", "bentoml", "bento")):
        _add_ai_surface(surfaces, "model-serving", "Model serving API", "high", ["Model-serving framework marker in banner or response"])

    if _path_matches(paths, ("/api/sessions", "/api/kernels")) or "jupyter" in banner or "jupyter" in preview:
        _add_ai_surface(surfaces, "notebook", "Jupyter notebook/server", "high", ["Jupyter API endpoint or marker exposed"])

    if _path_matches(paths, ("/api/v1/prediction", "/api/v1/chatflows", "/api/v1/credentials", "/v1/chat-messages", "/api/workspace", "/api/workspaces")):
        _add_ai_surface(surfaces, "ai-workflow", "AI workflow/chatbot builder", "high", ["Workflow/chatflow or hosted chat endpoint exposed"])
    elif any(marker in banner or marker in preview for marker in ("flowise", "dify", "anythingllm")):
        _add_ai_surface(surfaces, "ai-workflow", "Possible AI workflow/chatbot builder", "medium", ["Workflow platform marker in banner or response"])

    if _path_matches(paths, ("/sdapi/v1/sd-models", "/sdapi/v1/options", "/object_info", "/system_stats")):
        _add_ai_surface(surfaces, "image-generation", "Image-generation API", "high", ["Stable Diffusion or ComfyUI endpoint exposed"])

    ordered = sorted(
        surfaces.values(),
        key=lambda item: ({"high": 3, "medium": 2, "low": 1}.get(item["confidence"], 0), item["label"]),
        reverse=True,
    )
    return ordered


def ai_surface_lines(llm_enum: Dict[str, Any]) -> List[str]:
    surfaces = llm_enum.get("ai_surfaces", [])
    profile = llm_enum.get("agent_profile") or {}
    ai_paths_mode = bool(llm_enum.get("ai_paths_mode"))
    header = bold("AI attack pathfinder:", C.CYAN)

    if not surfaces and not profile:
        if ai_paths_mode:
            return [
                header,
                "  No known AI/ML/RAG fingerprint inferred from probes.",
                f"  {bold('Next:', C.YELLOW)} inspect OpenAPI/docs manually, check auth on interesting 200/401/403 paths, then broaden with web/content discovery.",
            ]
        return []

    lines = [header]

    # Inferred agent role + architecture + capabilities (from endpoint/route names).
    if profile:
        lines.append(f"  {bold('Agent profile:', C.CYAN)} {bold(profile.get('role', 'AI agent'), C.RED)}")
        arch = profile.get("architecture")
        framework = profile.get("framework")
        if arch and arch != "unknown":
            arch_labels = {
                "multi-agent": "Multi-agent / A2A system",
                "tool-server": "Tool server (MCP)",
                "vector-store": "Embedding / vector store",
                "rag": "RAG / knowledge-base pipeline",
                "single-agent": "Single agent",
            }
            arch_str = arch_labels.get(arch, arch)
            if framework:
                arch_str = f"{arch_str} - {framework}"
            lines.append(f"    {bold('Architecture:', C.CYAN)} {arch_str}")
        caps = profile.get("capabilities", [])
        if caps:
            dangerous = {"code-execution", "tool-calling", "mcp-tooling", "orchestration", "agent-discovery"}
            cap_str = ", ".join(color(c, C.BOLD + C.RED) if c in dangerous else c for c in caps)
            lines.append(f"    Capabilities: {cap_str}")
        signals = [paths[0] for paths in (profile.get("evidence", {}).get(c) for c in caps) if paths]
        if signals:
            lines.append(f"    {color('Signals:', C.GREY)} {', '.join(dict.fromkeys(signals))}")

    # Unauthenticated vector store = read the source chunks directly (plaintext first).
    vstore = llm_enum.get("vector_store") or {}
    if vstore.get("collections") is not None and vstore.get("unauthenticated"):
        count = vstore.get("collection_count", 0)
        lines.append(f"  {bold('Unauthenticated vector store:', C.RED)} {vstore.get('engine')} - {count} collection(s)")
        cols = vstore.get("collections") or []
        if cols:
            shown = ", ".join(cols[:8]) + (" ..." if len(cols) > 8 else "")
            lines.append(f"    {color('Collections:', C.GREY)} {shown}")
        lines.append(f"    {bold('Next:', C.YELLOW)} dump payloads read-only and grep for secrets/hosts/paths before any inversion ({vstore.get('url')}).")

    # Confirmed MCP tool inventory: inferred capability -> real tools.
    mcp_tools = llm_enum.get("mcp_tools") or {}
    if mcp_tools.get("tools"):
        lines.append(f"  {bold('Confirmed MCP tools:', C.RED)} {mcp_tools.get('tool_count')} via {mcp_tools.get('path')}")
        dangerous_cat = {"code-execution", "filesystem-write", "database-write", "secrets/identity"}
        for tool in mcp_tools["tools"][:12]:
            cats = tool.get("categories") or []
            cat_str = ", ".join(color(c, C.BOLD + C.RED) if c in dangerous_cat else c for c in cats)
            suffix = f"  [{cat_str}]" if cats else ""
            lines.append(f"    {color('-', C.GREY)} {tool.get('name')}{suffix}")

    # Confirmed A2A / agent-discovery documents.
    cards = llm_enum.get("agent_cards") or []
    if cards:
        card_paths = ", ".join(dict.fromkeys(c.get("path") for c in cards))
        lines.append(f"  {bold('Agent-discovery documents:', C.RED)} {card_paths}")
        lines.append(f"    {bold('Next:', C.YELLOW)} record advertised capabilities/endpoints; test for a self-service registration route (rogue-agent risk).")

    conf_colors = {"high": C.BOLD + C.RED, "medium": C.BOLD + C.YELLOW, "low": C.GREY}
    for surface in surfaces:
        confidence = str(surface.get("confidence", "")).lower()
        conf_str = color(f"{surface['confidence']} confidence", conf_colors.get(confidence, C.GREY))
        lines.append(f"  {bold(surface['label'], C.RED)} ({conf_str})")
        for evidence in surface.get("evidence", [])[:3]:
            lines.append(f"    {color('Evidence:', C.GREY)} {evidence}")
        for step in surface.get("next_steps", [])[:4]:
            lines.append(f"    {bold('Next:', C.YELLOW)} {step}")
    return lines


def apply_openapi_response(result: Dict[str, Any], response: Dict[str, Any], url: str) -> None:
    result["openapi_url"] = url
    result["openapi_status"] = response.get("status")
    result["openapi_error"] = response.get("error", "")
    result["endpoints"] = []

    if not response.get("ok") and not result["openapi_error"]:
        result["openapi_error"] = "HTTP request failed"
    elif response.get("json") is not None:
        result["endpoints"] = parse_openapi_endpoints(response["json"])
    elif not result["openapi_error"]:
        result["openapi_error"] = "Response was not valid JSON"


def enumerate_llm_service(target: str,
                          service: Service,
                          endpoint_only: bool = False,
                          ai_paths_mode: bool = False,
                          active: bool = False) -> Dict[str, Any]:
    base_url = service_base_url(target, service)
    openapi_url = f"{base_url}{OPENAPI_CANDIDATE_PATHS[0]}"
    openapi_response = http_request(openapi_url)

    result: Dict[str, Any] = {
        "base_url": base_url,
        "endpoint_only": endpoint_only,
        "ai_paths_mode": ai_paths_mode,
        "openapi_url": "",
        "openapi_status": None,
        "openapi_error": "",
        "endpoints": [],
        "probe_count": len(LLM_PROBE_PATHS),
        "probe_hits": [],
        "ai_surfaces": [],
        "agent_profile": {},
        "vector_store": {},
        "mcp_tools": {},
        "agent_cards": [],
        "chat_path": "",
    }

    apply_openapi_response(result, openapi_response, openapi_url)
    if not result["endpoints"]:
        for openapi_path in OPENAPI_CANDIDATE_PATHS[1:]:
            candidate_url = f"{base_url}{openapi_path}"
            candidate_response = http_request(candidate_url)
            candidate_endpoints = parse_openapi_endpoints(candidate_response.get("json"))
            if candidate_endpoints:
                apply_openapi_response(result, candidate_response, candidate_url)
                break

    if endpoint_only:
        result["ai_surfaces"] = infer_ai_surfaces(service, result)
        result["agent_profile"] = infer_agent_profile(result)
        return result

    result["probe_hits"] = probe_llm_paths(base_url)
    result["ai_surfaces"] = infer_ai_surfaces(service, result)
    result["agent_profile"] = infer_agent_profile(result)

    # "Plaintext first": if this looks like a vector store, try to list its
    # collections read-only. An unauthenticated listing is the highest-value RAG win.
    surface_keys = {s.get("key") for s in result["ai_surfaces"] if isinstance(s, dict)}
    architecture = result["agent_profile"].get("architecture")
    if architecture == "vector-store" or "rag-vector" in surface_keys:
        result["vector_store"] = enumerate_vector_store(base_url)

    # Active confirmation: turn inferred MCP/A2A capability into a real tool
    # inventory / agent-card list. Still read-only (initialize + tools/list, GET
    # agent cards); enabled by the default full AI enumeration mode.
    if active:
        probe_paths = {str(hit.get("path", "")).lower() for hit in result["probe_hits"]}
        if architecture == "tool-server" or "agent-mcp" in surface_keys \
                or any(p in probe_paths for p in ("/mcp", "/mcp/", "/sse")):
            result["mcp_tools"] = enumerate_mcp_tools(base_url)
        if architecture == "multi-agent" \
                or any(p in probe_paths for p in ("/.well-known/agent.json", "/agents", "/a2a")):
            result["agent_cards"] = fetch_agent_cards(base_url)

    # Record whether a chat/completions endpoint exists, across common stacks
    # (/chat, Ollama /api/chat, OpenAI /v1/chat/completions, ...). Enumeration
    # only - no prompt is sent. A 405 (GET not allowed) still counts: it exists.
    chat_path = next(
        (endpoint["path"] for endpoint in result["endpoints"] if _is_chat_endpoint(endpoint.get("path", ""))),
        "",
    )
    if not chat_path:
        chat_path = next(
            (hit["path"] for hit in result["probe_hits"] if _is_chat_endpoint(hit.get("path", ""))),
            "",
        )
    result["chat_path"] = chat_path

    return result


def run_llm_enumeration(target: str,
                        tcp_services: List[Service],
                        endpoint_only: bool = False,
                        probe_all_http: bool = False,
                        ai_paths_mode: bool = False,
                        active: bool = False) -> None:
    for service in tcp_services:
        if not resembles_llm_service(service) and not (probe_all_http and is_http_like_service(service)):
            continue

        port = service.get("port", "")
        action = "checking OpenAPI endpoints" if endpoint_only else "probing endpoints and common paths"
        info(f"{target}:{port}: LLM/API-like service found; {action}")
        service["llm_enum"] = enumerate_llm_service(
            target,
            service,
            endpoint_only=endpoint_only,
            ai_paths_mode=ai_paths_mode,
            active=active,
        )


def llm_enum_lines(llm_enum: Dict[str, Any]) -> List[str]:
    endpoint_only = bool(llm_enum.get("endpoint_only"))
    lines: List[str] = [bold("LLM/API endpoint enum:" if endpoint_only else "LLM/API enum:", C.CYAN)]
    status = llm_enum.get("openapi_status")
    status_text = f"status {status}" if status is not None else "no status"

    if llm_enum.get("openapi_error"):
        lines.append(f"  OpenAPI: {status_text}; {llm_enum['openapi_error']}")
    else:
        lines.append(f"  OpenAPI: {status_text}; {llm_enum.get('openapi_url', '')}")

    endpoints = llm_enum.get("endpoints", [])
    if endpoints:
        lines.append("  Endpoints:")
        for endpoint in endpoints:
            lines.append(f"    {endpoint['method']:<6} {endpoint['path']}")
    else:
        lines.append("  Endpoints: none found")

    if endpoint_only:
        return lines

    probe_hits = llm_enum.get("probe_hits", [])
    probe_count = llm_enum.get("probe_count", len(LLM_PROBE_PATHS))
    if probe_hits:
        lines.append(f"  Path probes: {len(probe_hits)} interesting of {probe_count} checked")
        for hit in probe_hits:
            status = hit.get("status", "")
            line = f"    {status:<3} {hit.get('path', '')}"
            if hit.get("preview"):
                line += f" - {hit['preview']}"
            lines.append(line)
            for json_line in hit.get("json_preview_lines", []):
                lines.append(f"      {json_line}")
    else:
        lines.append(f"  Path probes: no interesting responses from {probe_count} checked")

    if llm_enum.get("chat_path"):
        lines.append(f"  {bold('Chat endpoint discovered:', C.GREEN)} {llm_enum['chat_path']} (test prompt injection manually)")
    else:
        lines.append(color("  Chat endpoint: not found in OpenAPI or path probes", C.GREY))

    lines.extend(ai_surface_lines(llm_enum))

    return lines


# =========================
# Scan logic
# =========================

def host_fingerprint_scan(target: str,
                          outdir: Optional[Path],
                          ports: Optional[List[int]] = None) -> Dict:
    with tempfile.TemporaryDirectory(prefix="nmapwrap_") as tmpdir:
        xml_path = Path(tmpdir) / "host_fingerprint.xml"

        cmd = [
            "nmap",
            "-O",
            "--osscan-guess",
            "--max-os-tries", "1",
            "-v",
            "--stats-every", "5s",
        ]

        if ports:
            cmd.extend(["-p", ",".join(str(port) for port in ports)])
        else:
            cmd.extend(["--top-ports", str(HOST_FINGERPRINT_TOP_PORTS)])

        cmd.extend(["-oX", str(xml_path), target])

        rc, output = run_nmap_with_progress(cmd, target, phase="HOST-FP", proto="")

        if rc not in (0, 1) or not xml_path.exists():
            return {
                "ip": target,
                "hostname": "",
                "extra": {},
                "nmap_output": output,
            }

        if outdir:
            shutil.copy2(xml_path, outdir / "host_fingerprint.xml")

        try:
            root = parse_xml_file(xml_path)
        except RuntimeError:
            return {
                "ip": target,
                "hostname": "",
                "extra": {},
                "nmap_output": output,
            }

        host_el = root.find("host")
        if host_el is None:
            return {
                "ip": target,
                "hostname": "",
                "extra": {},
                "nmap_output": output,
            }

        ip_addr, hostname = get_host_identifier(host_el)
        extra = get_extra_host_info(host_el)
        return {
            "ip": ip_addr,
            "hostname": hostname,
            "extra": extra,
            "nmap_output": output,
        }


def localhost_fingerprint_scan(target: str, outdir: Optional[Path]) -> Dict:
    hostname = socket.gethostname()
    extra = {"os_guess": format_platform_os_guess()}
    output = f"local-platform: {extra['os_guess']}"

    if outdir:
        write_text(outdir / "host_fingerprint.txt", output + "\n")

    return {
        "ip": "127.0.0.1" if target.strip().lower() != "::1" else "::1",
        "hostname": hostname,
        "extra": extra,
        "nmap_output": output,
    }


def localhost_tcp_discovery_scan(target: str,
                                 outdir: Optional[Path],
                                 ports: Optional[List[int]] = None) -> Dict:
    fingerprint = localhost_fingerprint_scan(target, outdir)
    selected_ports = ports if ports else list(range(1, 65536))
    open_ports: List[int] = []
    completed = 0
    last_render = 0.0
    worker_count = min(LOCALHOST_SCAN_WORKERS, max(32, len(selected_ports)))

    def check_port(port: int) -> Optional[int]:
        sock = connect_to_localhost(target, port)
        if sock is None:
            return None
        try:
            return port
        finally:
            try:
                sock.close()
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(check_port, port): port for port in selected_ports}
        for future in as_completed(future_map):
            completed += 1
            port = future.result()
            if port is not None:
                open_ports.append(port)

            now = time.time()
            if now - last_render >= 0.2:
                progress(
                    f"DISCOVERY {target} | checked {completed}/{len(selected_ports)} ports | "
                    f"open tcp ports found: {len(open_ports)}"
                )
                last_render = now

    clear_progress_line()
    open_ports.sort()
    output = "\n".join(f"Discovered open port {port}/tcp on localhost" for port in open_ports)

    if outdir:
        write_text(outdir / "tcp_discovery.txt", output + ("\n" if output else ""))

    return {
        "target": target,
        "ip": fingerprint.get("ip", "127.0.0.1"),
        "hostname": fingerprint.get("hostname", ""),
        "extra": fingerprint.get("extra", {}),
        "open_ports": open_ports,
        "nmap_output": output,
    }


def localhost_tcp_service_scan(target: str, ports: List[int], outdir: Optional[Path]) -> Dict:
    services = [local_service_probe(target, port) for port in ports]
    services = sorted(services, key=lambda service: int(service["port"]))
    output_lines = [f"{svc['port']}/tcp {service_banner(svc)}" for svc in services]

    if outdir:
        write_text(outdir / "tcp_services.txt", "\n".join(output_lines) + ("\n" if output_lines else ""))

    return {
        "ip": "127.0.0.1" if target.strip().lower() != "::1" else "::1",
        "hostname": socket.gethostname(),
        "extra": {},
        "services": services,
        "nmap_output": "\n".join(output_lines),
    }


def tcp_discovery_scan(target: str,
                       outdir: Optional[Path],
                       timing: str,
                       ports: Optional[List[int]] = None) -> Dict:
    with tempfile.TemporaryDirectory(prefix="nmapwrap_") as tmpdir:
        xml_path = Path(tmpdir) / "tcp_discovery.xml"
        port_arg = ",".join(str(port) for port in ports) if ports else "-"
        fingerprint = host_fingerprint_scan(target, outdir, ports)

        cmd = [
            "nmap",
            "-Pn",
            f"-{timing}",
            f"-p{port_arg}",
            "--open",
            "-v",
            "--stats-every", "5s",
            "-oX", str(xml_path),
            target,
        ]

        rc, output = run_nmap_with_progress(cmd, target, phase="DISCOVERY", proto="tcp")

        if rc not in (0, 1):
            raise RuntimeError(f"nmap TCP discovery failed for {target}")

        if outdir:
            shutil.copy2(xml_path, outdir / "tcp_discovery.xml")

        root = parse_xml_file(xml_path)
        host_el = root.find("host")
        if host_el is None:
            return {
                "target": target,
                "ip": fingerprint.get("ip", target),
                "hostname": fingerprint.get("hostname", ""),
                "extra": fingerprint.get("extra", {}),
                "open_ports": [],
            }

        open_ports = parse_open_ports(host_el, proto_filter="tcp")
        ip_addr, hostname = get_host_identifier(host_el)
        if ip_addr == "unknown":
            ip_addr = fingerprint.get("ip", target)
        hostname = hostname or fingerprint.get("hostname", "")

        return {
            "target": target,
            "ip": ip_addr,
            "hostname": hostname,
            "extra": fingerprint.get("extra", {}),
            "open_ports": open_ports,
            "nmap_output": output,
        }


def tcp_service_scan(target: str, ports: List[int], outdir: Optional[Path],
                     loot_xml_dir: Optional[Path] = None) -> Dict:
    with tempfile.TemporaryDirectory(prefix="nmapwrap_") as tmpdir:
        xml_path = Path(tmpdir) / "tcp_services.xml"
        port_str = ",".join(str(p) for p in ports)

        cmd = [
            "nmap",
            "-Pn",
            "-T3",
            "-sC",
            "-sV",
            "-v",
            "--stats-every", "5s",
            "-p", port_str,
            "-oX", str(xml_path),
            target,
        ]

        rc, output = run_nmap_with_progress(cmd, target, phase="SERVICE-ENUM", proto="tcp")

        if rc not in (0, 1):
            raise RuntimeError(f"nmap TCP service scan failed for {target}")

        if outdir:
            shutil.copy2(xml_path, outdir / "tcp_services.xml")
        # Drop the service-scan XML into the loot dir so PathFinder gets this host's
        # services/versions/OS (the whole exploit-mapping + service-reuse pipeline).
        if loot_xml_dir:
            loot_xml_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(xml_path, loot_xml_dir / "nmap.xml")

        root = parse_xml_file(xml_path)
        host_el = root.find("host")
        if host_el is None:
            return {"services": [], "extra": {}}

        ip_addr, hostname = get_host_identifier(host_el)
        extra = get_extra_host_info(host_el)
        services = parse_service_details(host_el, proto_filter="tcp")

        return {
            "ip": ip_addr,
            "hostname": hostname,
            "extra": extra,
            "services": services,
            "nmap_output": output,
        }


def udp_scan(target: str, top_ports: int, outdir: Optional[Path]) -> Dict:
    with tempfile.TemporaryDirectory(prefix="nmapwrap_") as tmpdir:
        xml_path = Path(tmpdir) / "udp_top_ports.xml"

        cmd = [
            "nmap",
            "-Pn",
            "-T3",
            "-sU",
            "--top-ports", str(top_ports),
            "-v",
            "--stats-every", "5s",
            "-oX", str(xml_path),
            target,
        ]

        rc, output = run_nmap_with_progress(cmd, target, phase="UDP", proto="udp")

        if rc not in (0, 1):
            raise RuntimeError(f"nmap UDP scan failed for {target}")

        if outdir:
            shutil.copy2(xml_path, outdir / "udp_top_ports.xml")

        root = parse_xml_file(xml_path)
        host_el = root.find("host")
        if host_el is None:
            return {"udp_services": []}

        udp_services = parse_service_details(host_el, proto_filter="udp")
        return {
            "udp_services": udp_services,
            "nmap_output": output,
        }


# =========================
# Output
# =========================

def print_host_summary(ip_addr: str,
                       hostname: str,
                       extra: Dict[str, str],
                       tcp_services: List[Service],
                       udp_services: List[Service]) -> None:
    print(bold("=" * 88, C.CYAN))
    host_line = f"Host: {ip_addr}"
    if hostname:
        host_line += f" ({hostname})"
    print(bold(host_line, C.CYAN))

    if extra.get("mac"):
        mac_line = f"MAC: {extra['mac']}"
        if extra.get("vendor"):
            mac_line += f" [{extra['vendor']}]"
        print(color(mac_line, C.GREY))

    if extra.get("lastboot"):
        print(color(f"Last boot: {extra['lastboot']}", C.GREY))

    if extra.get("os_guess"):
        print(f"{bold('OS guess:', C.YELLOW)} {extra['os_guess']}")

    print(color("-" * 88, C.GREY))

    def _print_service_table(services):
        print(color(f"{'PORT':<10}{'PROTO':<8}{'SERVICE INFO'}", C.GREY))
        print(color("-" * 88, C.GREY))
        for svc in services:
            port_col = color(f"{svc['port']:<10}", C.BOLD + C.GREEN)
            print(f"{port_col}{svc['protocol']:<8}{service_banner(svc)}")
            if svc.get("llm_enum"):
                for line in llm_enum_lines(svc["llm_enum"]):
                    print(f"{'':<18}{line}")
            if svc["scripts"]:
                for sline in svc["scripts"].splitlines():
                    print(color(f"{'':<18}└─ {sline}", C.GREY))

    if tcp_services:
        print(bold("TCP", C.CYAN))
        _print_service_table(tcp_services)
    else:
        print(color("No open TCP ports discovered.", C.GREY))

    if udp_services:
        print(color("-" * 88, C.GREY))
        print(bold("UDP", C.CYAN))
        _print_service_table(udp_services)

    print()


def write_host_report(outdir: Path,
                      ip_addr: str,
                      hostname: str,
                      extra: Dict[str, str],
                      tcp_services: List[Service],
                      udp_services: List[Service]) -> None:
    lines = []
    lines.append(f"Host: {ip_addr}" + (f" ({hostname})" if hostname else ""))
    if extra.get("mac"):
        mac_line = f"MAC: {extra['mac']}"
        if extra.get("vendor"):
            mac_line += f" [{extra['vendor']}]"
        lines.append(mac_line)
    if extra.get("lastboot"):
        lines.append(f"Last boot: {extra['lastboot']}")
    if extra.get("os_guess"):
        lines.append(f"OS guess: {extra['os_guess']}")
    lines.append("")
    lines.append("TCP")
    lines.append("-" * 60)

    if tcp_services:
        for svc in tcp_services:
            lines.append(f"{svc['port']}/{svc['protocol']}: {service_banner(svc)}")
            if svc.get("llm_enum"):
                for line in llm_enum_lines(svc["llm_enum"]):
                    lines.append(f"  {line}")
            if svc["scripts"]:
                for sline in svc["scripts"].splitlines():
                    lines.append(f"  - {sline}")
    else:
        lines.append("No open TCP ports discovered.")

    lines.append("")
    lines.append("UDP")
    lines.append("-" * 60)

    if udp_services:
        for svc in udp_services:
            lines.append(f"{svc['port']}/{svc['protocol']}: {service_banner(svc)}")
            if svc["scripts"]:
                for sline in svc["scripts"].splitlines():
                    lines.append(f"  - {sline}")
    else:
        lines.append("No open UDP ports discovered or UDP scan not enabled.")

    write_text(outdir / "summary.txt", "\n".join(lines) + "\n")


def write_csv_summary(csv_path: Path, rows: List[Dict[str, str]]) -> None:
    fieldnames = [
        "ip",
        "hostname",
        "protocol",
        "port",
        "service",
        "product",
        "version",
        "extrainfo",
        "banner",
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


# =========================
# PathFinder bridge: next-step suggestions
# =========================
#
# Given the services discovered in stage 2, suggest the follow-up enumeration
# tools PathFinder has (or will have) parsers for, with example commands that
# write output in a format PathFinder's `scan` auto-detector can consume.
#
# Workflow:
#   one-shot-enum <target> --pathfinder-suggest -> write commands into the loot dir
#                                       ->   pathfinder scan <loot>/

LOOT_DIR = "loot"
PATHFINDER_PROVENANCE_MANIFEST = "_pathfinder_provenance.json"
DEFAULT_WEB_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
DEFAULT_USER_WORDLIST = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PATHFINDER_SCAN_CMD = "python3 -m main.pathfinder scan"
DEFAULT_FFUF_MAXTIME = 180

# --pathfinder concurrency: one lane per host, this many tools at once within a lane.
# Concurrency auto-scales with the number of hosts (lanes run in parallel), so a
# single box still parallelises while no host is ever hammered by more than this.
PER_HOST_LANE = 2
# Kill a tool that produces no output for this many seconds (a hang); 0 disables.
DEFAULT_RUN_IDLE_TIMEOUT = 180
# Wall-clock ceiling (seconds) for a single nmap invocation, so one filtered/slow
# host on a -p- / -sU sweep can't pin a worker forever (--run-timeout only covers
# the recon tools, not nmap). 0 disables. Set from --scan-timeout in main();
# run_nmap_with_progress reads this global at call time.
DEFAULT_SCAN_TIMEOUT = 1800
NMAP_SCAN_TIMEOUT = DEFAULT_SCAN_TIMEOUT

WEB_PORTS = {80, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8180,
             8443, 8444, 8800, 8888, 9000, 9090, 9443}
WEB_HTTPS_PORTS = {443, 8443, 8444, 9443, 2083, 2087, 2096}
SMB_PORTS = {139, 445}
LDAP_PORTS = {389, 636, 3268, 3269}
KERBEROS_PORTS = {88}
SNMP_PORTS = {161}
NFS_PORTS = {111, 2049}
REDIS_PORTS = {6379}
RSYNC_PORTS = {873}
SMTP_PORTS = {25, 465, 587}

DOMAIN_PLACEHOLDER = "<domain>"
USER_PLACEHOLDER = "<user>"
PASS_PLACEHOLDER = "<pass>"
PLACEHOLDERS = (DOMAIN_PLACEHOLDER, USER_PLACEHOLDER, PASS_PLACEHOLDER)
DNS_DOMAIN_RE = re.compile(r"(?i)\b(?:DNS_Domain_Name|Domain):\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b")
CERT_CN_RE = re.compile(r"(?i)\bcommonName=([a-z0-9_-]+\.[a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b")


def _has_placeholder(value: str) -> bool:
    return any(token in value for token in PLACEHOLDERS)


def _suggestion_has_placeholder(s: Dict[str, Any]) -> bool:
    return _has_placeholder(str(s.get("command", "")))


def _clean_dns_domain(candidate: str) -> str:
    domain = candidate.strip().strip(".,;:)").lower()
    if len(domain) > 253 or "." not in domain:
        return ""
    labels = domain.split(".")
    if len(labels) < 2:
        return ""
    for label in labels:
        if not label or len(label) > 63:
            return ""
        if label.startswith("-") or label.endswith("-"):
            return ""
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return ""
    return domain


def _domain_from_fqdn(fqdn: str) -> str:
    clean = _clean_dns_domain(fqdn)
    if not clean:
        return ""
    labels = clean.split(".")
    if len(labels) >= 3:
        return ".".join(labels[1:])
    return clean


def infer_ad_domain(tcp_services: List[Service]) -> str:
    """Infer an AD DNS domain from Nmap LDAP/RDP script and service metadata."""
    fallback = ""
    for service in tcp_services:
        blob = "\n".join([
            str(service.get("scripts", "")),
            str(service.get("extrainfo", "")),
            str(service.get("product", "")),
        ])
        for match in DNS_DOMAIN_RE.finditer(blob):
            domain = _clean_dns_domain(match.group(1))
            if domain:
                return domain
        if not fallback:
            cn_match = CERT_CN_RE.search(blob)
            if cn_match:
                fallback = _domain_from_fqdn(cn_match.group(1))
    return fallback


def host_loot_dir(loot: str, host: str) -> str:
    """Per-host loot subdirectory (forward slashes for the generated shell commands).

    The directory name is the host so PathFinder can attribute every file inside
    it to that host. safe_name keeps IPs/hostnames intact (dots/hyphens preserved).
    """
    return f"{loot}/{safe_name(host)}"


def warn_stale_loot(loot: str, targets: List[str]) -> None:
    """Warn if the loot dir already holds host subdirs that aren't in this run's
    target set. PathFinder analyses the whole loot tree, so leftover host dirs from a
    previous engagement would be synthesised alongside the current data. We only
    warn (never delete) - clearing another engagement's loot is the operator's call.
    """
    root = Path(loot)
    if not root.is_dir():
        return
    expected = {safe_name(t) for t in targets}
    try:
        stale = sorted(
            entry.name for entry in root.iterdir()
            if entry.is_dir() and not entry.name.startswith("_") and entry.name not in expected
        )
    except OSError:
        return
    if stale:
        warn(f"Loot dir '{loot}/' already contains host data not in this run: {', '.join(stale)}.")
        warn("PathFinder analyses the whole loot dir; move/clear stale hosts or pass "
             "--loot-dir <fresh> to avoid mixing engagements.")


def write_llm_enum_loot(host: str, service: Service, loot: str,
                        discovery_command: str = "") -> Optional[Path]:
    """Write a service's LLM/AI surface enumeration into the loot dir as a
    PathFinder-consumable JSON so PathFinder's AI/LLM rules can synthesise attack
    paths from it. Returns the written path, or None if there's nothing to emit."""
    llm_enum = service.get("llm_enum")
    # Hand off if we recognised a framework surface OR inferred an agent role
    # (custom agents often match no framework fingerprint but are clearly AI).
    if not isinstance(llm_enum, dict) or not (llm_enum.get("ai_surfaces") or llm_enum.get("agent_profile")):
        return None
    try:
        port_int = int(service.get("port"))
    except (TypeError, ValueError):
        port_int = None
    payload = {
        "tool": "one-shot-enum",
        "type": "llm_enum",
        "discovery_command": discovery_command or None,
        "host": host,
        "port": port_int,
        "base_url": llm_enum.get("base_url"),
        "service": {
            "name": service.get("service", ""),
            "product": service.get("product", ""),
            "version": service.get("version", ""),
            "banner": service_banner(service),
        },
        "openapi_url": llm_enum.get("openapi_url"),
        "openapi_status": llm_enum.get("openapi_status"),
        "openapi_error": llm_enum.get("openapi_error"),
        "endpoints": llm_enum.get("endpoints", []),
        "probe_count": llm_enum.get("probe_count"),
        "probe_hits": [
            {
                "path": hit.get("path"),
                "status": hit.get("status"),
                "content_type": hit.get("content_type", ""),
                "preview": hit.get("preview", ""),
                "json_preview_lines": hit.get("json_preview_lines", []),
            }
            for hit in llm_enum.get("probe_hits", []) if isinstance(hit, dict)
        ],
        "chat_path": llm_enum.get("chat_path", ""),
        "agent_profile": llm_enum.get("agent_profile") or {},
        "vector_store": llm_enum.get("vector_store") or {},
        "mcp_tools": llm_enum.get("mcp_tools") or {},
        "agent_cards": llm_enum.get("agent_cards") or [],
        "ai_surfaces": [
            {"key": s.get("key"), "label": s.get("label"),
             "confidence": s.get("confidence"), "evidence": s.get("evidence", []),
             "next_steps": s.get("next_steps", [])}
            for s in llm_enum.get("ai_surfaces", []) if isinstance(s, dict)
        ],
    }
    host_dir = Path(host_loot_dir(loot, host))
    host_dir.mkdir(parents=True, exist_ok=True)
    out = host_dir / f"llm_enum_{safe_name(str(port_int) if port_int is not None else 'x')}.json"
    write_text(out, json.dumps(payload, indent=2))
    return out


def _suggestion(host: str, group: str, tool: str, command: str, parser: str,
                pending: bool = False, gated: bool = False, shell: str = "bash",
                note: str = "", output_file: str = "") -> Dict[str, Any]:
    return {
        "host": host, "group": group, "tool": tool, "command": command,
        "parser": parser, "pending": pending, "gated": gated, "shell": shell,
        "note": note, "output_file": output_file,
    }


def _svc_port(service: Service) -> int:
    try:
        return int(str(service.get("port", "0")))
    except ValueError:
        return 0


def _svc_name(service: Service) -> str:
    return service.get("service", "").lower()


def _is_web_service(service: Service) -> bool:
    return "http" in _svc_name(service) or _svc_port(service) in WEB_PORTS


def _web_scheme(service: Service) -> str:
    if ("https" in _svc_name(service)
            or service.get("tunnel", "").lower() == "ssl"
            or _svc_port(service) in WEB_HTTPS_PORTS):
        return "https"
    return "http"


def _looks_wordpress(service: Service) -> bool:
    blob = " ".join([
        service.get("product", ""), service.get("extrainfo", ""),
        service.get("scripts", ""),
    ]).lower()
    return "wordpress" in blob or "wp-content" in blob


def _lootpath(loot: str, name: str) -> str:
    """A shlex-quoted loot file/dir path, so a --loot-dir with spaces or shell
    metacharacters can't break the generated bash command or the recon script."""
    return shlex.quote(f"{loot}/{name}")


def _lootfile(loot: str, name: str) -> str:
    """Unquoted counterpart to _lootpath for structured provenance metadata."""
    return f"{loot}/{name}"


def _web_suggestions(host: str, service: Service, loot: str, wordlist: str,
                     power: bool = False) -> List[Dict[str, Any]]:
    scheme = _web_scheme(service)
    port = _svc_port(service)
    base = f"{scheme}://{host}:{port}"
    group = f"web {scheme}:{port}"
    k = " -k" if scheme == "https" else ""
    wl = shlex.quote(wordlist)
    out = [
        _suggestion(host, group, "curl",
                    f"curl{k} --location --silent --show-error --max-time 30 {base}/ "
                    f"--output {_lootpath(loot, f'webpage_{scheme}_{port}.html')}",
                    "webpage_html", output_file=_lootfile(loot, f"webpage_{scheme}_{port}.html")),
        _suggestion(host, group, "whatweb",
                    f"whatweb -a3 {base} --log-json={_lootpath(loot, f'whatweb_{port}.json')}", "whatweb_json",
                    output_file=_lootfile(loot, f"whatweb_{port}.json")),
        _suggestion(host, group, "ffuf",
                    f"ffuf -u {base}/FUZZ -w {wl}{k} -maxtime {DEFAULT_FFUF_MAXTIME} "
                    f"-of json -o {_lootpath(loot, f'ffuf_{port}.json')}",
                    "ffuf_json", output_file=_lootfile(loot, f"ffuf_{port}.json")),
        _suggestion(host, group, "nikto",
                    f"nikto -h {base} -Format json -o {_lootpath(loot, f'nikto_{port}.json')}", "nikto_json",
                    output_file=_lootfile(loot, f"nikto_{port}.json")),
    ]
    if power:
        out.extend([
            _suggestion(host, group, "nuclei",
                        f"nuclei -u {base} -jsonl -o {_lootpath(loot, f'nuclei_{port}.jsonl')}", "nuclei_jsonl",
                        output_file=_lootfile(loot, f"nuclei_{port}.jsonl")),
        ])
    if _looks_wordpress(service):
        out.append(_suggestion(host, group, "wpscan",
                   f"wpscan --url {base} --format json -o {_lootpath(loot, f'wpscan_{port}.json')} --disable-tls-checks",
                   "wpscan_json", output_file=_lootfile(loot, f"wpscan_{port}.json")))
    return out


def _smb_suggestions(host: str, loot: str) -> List[Dict[str, Any]]:
    tag = safe_name(host)
    return [
        _suggestion(host, "smb", "enum4linux-ng",
                    f"enum4linux-ng -A -oJ {_lootpath(loot, f'enum4linux_{tag}')} {host}", "enum4linux_json",
                    output_file=_lootfile(loot, f"enum4linux_{tag}.json")),
        # tee (not >) so stdout still flows through the pipe the --run idle-timeout
        # watches; a plain redirect leaves the pipe silent and can get the tool killed.
        _suggestion(host, "smb", "smbmap",
                    f"smbmap -H {host} -u guest -p '' | tee {_lootpath(loot, f'smbmap_{tag}.txt')}", "smbmap_txt",
                    output_file=_lootfile(loot, f"smbmap_{tag}.txt")),
        _suggestion(host, "smb", "netexec",
                    f"nxc smb {host} --shares --users --log {_lootpath(loot, f'nxc_{tag}.log')}",
                    "netexec_log", output_file=_lootfile(loot, f"nxc_{tag}.log")),
    ]


def _snmp_suggestions(host: str, loot: str) -> List[Dict[str, Any]]:
    return [
        # tee (not >) so the --run idle-timeout sees output on the pipe; snmp-check
        # can walk a large MIB silently on stdout and would otherwise look hung.
        _suggestion(host, "snmp", "snmp-check",
                    f"snmp-check {host} -c public | tee {_lootpath(loot, f'snmp_{safe_name(host)}.txt')}", "snmp_txt",
                    output_file=_lootfile(loot, f"snmp_{safe_name(host)}.txt")),
    ]


def _nfs_suggestions(host: str, loot: str) -> List[Dict[str, Any]]:
    tag = safe_name(host)
    return [
        _suggestion(host, "nfs", "showmount",
                    f"showmount -e {host} | tee {_lootpath(loot, f'nfs_{tag}.txt')}", "nfs_txt",
                    output_file=_lootfile(loot, f"nfs_{tag}.txt")),
    ]


def _redis_suggestions(host: str, service: Service, loot: str) -> List[Dict[str, Any]]:
    port = _svc_port(service) or 6379
    return [
        _suggestion(host, f"redis:{port}", "redis-cli",
                    f"redis-cli -h {host} -p {port} INFO | tee {_lootpath(loot, f'redis_{port}.txt')}",
                    "redis_txt", output_file=_lootfile(loot, f"redis_{port}.txt")),
    ]


def _rsync_suggestions(host: str, loot: str) -> List[Dict[str, Any]]:
    tag = safe_name(host)
    return [
        _suggestion(host, "rsync", "rsync",
                    f"rsync --list-only rsync://{host}/ | tee {_lootpath(loot, f'rsync_{tag}.txt')}",
                    "rsync_txt", output_file=_lootfile(loot, f"rsync_{tag}.txt")),
    ]


def _smtp_suggestions(host: str, service: Service, loot: str, userlist: str) -> List[Dict[str, Any]]:
    port = _svc_port(service) or 25
    ul = shlex.quote(userlist)
    return [
        _suggestion(host, f"smtp:{port}", "smtp-user-enum",
                    f"smtp-user-enum -M VRFY -U {ul} -t {host} -p {port} | tee "
                    f"{_lootpath(loot, f'smtp_user_enum_{port}.txt')}",
                    "smtp_user_enum_txt", output_file=_lootfile(loot, f"smtp_user_enum_{port}.txt")),
    ]


def _ad_suggestions(host: str, loot: str, userlist: str, domain: str = "") -> List[Dict[str, Any]]:
    dom = domain or DOMAIN_PLACEHOLDER
    user, pw = USER_PLACEHOLDER, PASS_PLACEHOLDER
    domain_note = f"domain inferred from nmap: {domain}" if domain else ""
    ul = shlex.quote(userlist)
    return [
        _suggestion(host, "ad kerberos", "kerbrute",
                    f"kerbrute userenum -d {dom} --dc {host} {ul} -o {_lootpath(loot, 'kerbrute.txt')}",
                    "kerbrute_txt", note=domain_note,
                    output_file=_lootfile(loot, "kerbrute.txt")),
        _suggestion(host, "ad kerberos", "impacket-GetNPUsers",
                    f"impacket-GetNPUsers {dom}/ -dc-ip {host} -usersfile {ul} "
                    f"-format hashcat -outputfile {_lootpath(loot, 'getnpusers.txt')}", "getnpusers_hashes",
                    note=domain_note, output_file=_lootfile(loot, "getnpusers.txt")),
        _suggestion(host, "ad (needs creds)", "ldapdomaindump",
                    f"ldapdomaindump -u '{dom}\\{user}' -p '{pw}' {host} -o {_lootpath(loot, 'ldap/')}",
                    "ldapdomaindump_dir", gated=True),
        _suggestion(host, "ad (needs creds)", "impacket-GetUserSPNs",
                    f"impacket-GetUserSPNs {dom}/{user}:{pw} -dc-ip {host} -request "
                    f"-outputfile {_lootpath(loot, 'getuserspns.txt')}", "getuserspns_hashes", gated=True),
        _suggestion(host, "ad (needs creds)", "certipy",
                    f"certipy find -u {user}@{dom} -p '{pw}' -dc-ip {host} -json -output {_lootpath(loot, 'certipy')}",
                    "certipy_json", gated=True),
        _suggestion(host, "ad (needs creds)", "impacket-secretsdump",
                    f"impacket-secretsdump {dom}/{user}:{pw}@{host} | tee {_lootpath(loot, 'secretsdump.txt')}",
                    "secretsdump_txt", gated=True),
    ]


def _post_foothold_suggestions(host: str, loot: str) -> List[Dict[str, Any]]:
    tag = safe_name(host)
    return [
        _suggestion(host, "post-foothold (linux)", "linpeas",
                    f"./linpeas.sh | tee {_lootpath(loot, f'linpeas_{tag}.txt')}", "linpeas_txt", gated=True),
        _suggestion(host, "post-foothold (windows)", "winpeas",
                    f".\\winPEASany.exe > {loot}\\winpeas_{tag}.txt", "winpeas_txt",
                    gated=True, shell="powershell"),
        _suggestion(host, "post-foothold (windows)", "SharpHound",
                    f".\\SharpHound.exe -c All --outputdirectory {loot}\\sharphound_{tag}",
                    "sharphound_dir", gated=True, shell="powershell",
                    note="unzip the resulting .zip into that folder before scanning"),
    ]


def suggest_for_host(host: str,
                     tcp_services: List[Service],
                     udp_services: List[Service],
                     loot: str,
                     wordlist: str,
                     userlist: str,
                     power: bool = False) -> List[Dict[str, Any]]:
    suggestions: List[Dict[str, Any]] = []
    has_smb = False
    has_ad = False
    has_snmp = False
    has_nfs = False
    has_rsync = False

    # Per-host loot subdirectory so PathFinder attributes every file to this host
    # and files from different hosts never collide.
    host_loot = host_loot_dir(loot, host)

    for service in tcp_services:
        port = _svc_port(service)
        if _is_web_service(service):
            suggestions.extend(_web_suggestions(host, service, host_loot, wordlist, power=power))
        if _svc_name(service) in {"microsoft-ds", "netbios-ssn", "smb"} or port in SMB_PORTS:
            has_smb = True
        if "ldap" in _svc_name(service) or "kerberos" in _svc_name(service) \
                or port in LDAP_PORTS or port in KERBEROS_PORTS:
            has_ad = True
        if "nfs" in _svc_name(service) or "mountd" in _svc_name(service) or "rpcbind" in _svc_name(service) \
                or port in NFS_PORTS:
            has_nfs = True
        if "redis" in _svc_name(service) or port in REDIS_PORTS:
            suggestions.extend(_redis_suggestions(host, service, host_loot))
        if "rsync" in _svc_name(service) or port in RSYNC_PORTS:
            has_rsync = True
        if "smtp" in _svc_name(service) or port in SMTP_PORTS:
            suggestions.extend(_smtp_suggestions(host, service, host_loot, userlist))

    for service in list(udp_services) + list(tcp_services):
        if "snmp" in _svc_name(service) or _svc_port(service) in SNMP_PORTS:
            has_snmp = True
        if "nfs" in _svc_name(service) or "mountd" in _svc_name(service) or "rpcbind" in _svc_name(service) \
                or _svc_port(service) in NFS_PORTS:
            has_nfs = True
        if "rsync" in _svc_name(service) or _svc_port(service) in RSYNC_PORTS:
            has_rsync = True

    if has_smb:
        suggestions.extend(_smb_suggestions(host, host_loot))
    if has_snmp:
        suggestions.extend(_snmp_suggestions(host, host_loot))
    if has_nfs:
        suggestions.extend(_nfs_suggestions(host, host_loot))
    if has_rsync:
        suggestions.extend(_rsync_suggestions(host, host_loot))
    if has_ad:
        suggestions.extend(_ad_suggestions(host, host_loot, userlist, infer_ad_domain(tcp_services)))
    suggestions.extend(_post_foothold_suggestions(host, host_loot))

    seen: Set[Tuple[str, str, str]] = set()
    deduped: List[Dict[str, Any]] = []
    for s in suggestions:
        key = (s["host"], s["tool"], s["command"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(s)
    return deduped


def _ordered_groups(suggestions: List[Dict[str, Any]]) -> List[str]:
    groups: List[str] = []
    for s in suggestions:
        if s["group"] not in groups:
            groups.append(s["group"])
    return groups


def print_suggestions(host: str, suggestions: List[Dict[str, Any]]) -> None:
    if not suggestions:
        info(f"{host}: no PathFinder-relevant services found to suggest tooling for")
        return

    print(color(f"PathFinder next steps for {host}", C.BOLD))
    for group in _ordered_groups(suggestions):
        print(color(f"  {group}", C.CYAN))
        for s in [x for x in suggestions if x["group"] == group]:
            tags = []
            if s["pending"]:
                tags.append("parser pending")
            if s["gated"]:
                tags.append("needs creds/foothold")
            if _suggestion_has_placeholder(s):
                tags.append("edit placeholders")
            tag_text = color("  [" + ", ".join(tags) + "]", C.GREY) if tags else ""
            print(f"    {s['command']}{tag_text}")
            meta = f"-> {s['parser']}"
            if s["note"]:
                meta += f"; {s['note']}"
            print(color(f"      {meta}", C.GREY))
    print()


def _script_line(s: Dict[str, Any]) -> str:
    notes = [f"-> {s['parser']}"]
    if s["pending"]:
        notes.append("parser pending")
    if s["gated"]:
        notes.append("needs creds/foothold")
    if _suggestion_has_placeholder(s):
        notes.append("edit placeholders")
    if s["note"]:
        notes.append(s["note"])
    line = f"{s['command']}   # {'; '.join(notes)}"
    # Gated commands and unresolved placeholders are emitted commented-out so the
    # script never runs anything unattended that still needs operator context.
    return f"# {line}" if s["gated"] or _suggestion_has_placeholder(s) else line


def write_recon_scripts(outdir: Path,
                        all_suggestions: List[Dict[str, Any]],
                        loot: str) -> List[Path]:
    hosts: List[str] = []
    for s in all_suggestions:
        if s["host"] not in hosts:
            hosts.append(s["host"])

    # One loot subdirectory per host (plus its ldap/ subdir for ldapdomaindump).
    mkdir_targets = [loot]
    for host in hosts:
        hd = host_loot_dir(loot, host)
        mkdir_targets.extend([hd, f"{hd}/ldap"])

    bash_lines = [
        "#!/usr/bin/env bash",
        "# Generated by one-shot-enum --pathfinder-suggest. Review before running.",
        "# Live lines are unauthenticated recon; commented lines need creds/a foothold.",
        "set -u",
        "mkdir -p " + " ".join(shlex.quote(t) for t in mkdir_targets),
        "",
    ]
    ps_lines = [
        "# Generated by one-shot-enum --pathfinder-suggest. Run these on the target after a foothold.",
        "# All commands are commented out; uncomment and edit placeholders as needed.",
        "",
    ]
    has_ps = False

    for host in hosts:
        host_suggestions = [s for s in all_suggestions if s["host"] == host]
        bash_for_host = [s for s in host_suggestions if s["shell"] == "bash"]
        ps_for_host = [s for s in host_suggestions if s["shell"] == "powershell"]

        if bash_for_host:
            bash_lines.append(f"# ===== {host} =====")
            for group in _ordered_groups(bash_for_host):
                bash_lines.append(f"# --- {group} ---")
                for s in [x for x in bash_for_host if x["group"] == group]:
                    bash_lines.append(_script_line(s))
            bash_lines.append("")

        if ps_for_host:
            has_ps = True
            ps_lines.append(f"# ===== {host} =====")
            for s in ps_for_host:
                ps_lines.append(_script_line(s))
            ps_lines.append("")

    bash_lines.append(f"# When collection is done: {PATHFINDER_SCAN_CMD} {loot}/")
    ps_lines.append(f"# After transferring loot back: {PATHFINDER_SCAN_CMD} {loot}/")

    written: List[Path] = []
    bash_path = outdir / "pathfinder_recon.sh"
    write_text(bash_path, "\n".join(bash_lines) + "\n")
    written.append(bash_path)
    if has_ps:
        ps_path = outdir / "pathfinder_recon.ps1"
        write_text(ps_path, "\n".join(ps_lines) + "\n")
        written.append(ps_path)
    return written


def _ordered_hosts(suggestions: List[Dict[str, Any]]) -> List[str]:
    hosts: List[str] = []
    for s in suggestions:
        if s["host"] not in hosts:
            hosts.append(s["host"])
    return hosts


def runnable_suggestions(all_suggestions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Live, unauthenticated, kali-side commands only (never gated/placeholder ones)."""
    return [
        s for s in all_suggestions
        if not s["gated"] and s["shell"] == "bash" and not _suggestion_has_placeholder(s)
    ]


def _output_fingerprint(path: Optional[str]) -> Optional[Tuple[int, int, int]]:
    """Cheap identity used to prove a job created or changed its declared output."""
    if not path:
        return None
    try:
        stat = os.stat(path)
    except OSError:
        return None
    return stat.st_size, stat.st_mtime_ns, getattr(stat, "st_ino", 0)


def _write_pathfinder_provenance(loot: str, jobs: List[Dict[str, Any]]) -> Path:
    """Persist exact producer commands so PathFinder can join them to loot files."""
    loot_path = Path(loot)
    loot_path.mkdir(parents=True, exist_ok=True)
    manifest_path = loot_path / PATHFINDER_PROVENANCE_MANIFEST
    existing: Dict[str, Dict[str, Any]] = {}
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        for record in payload.get("records", []) if isinstance(payload, dict) else []:
            if isinstance(record, dict) and record.get("output_file"):
                existing[str(record["output_file"]).replace("\\", "/").lower()] = record
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        pass

    for job in jobs:
        output_file = job.get("output_file")
        if not output_file:
            continue
        output_after = _output_fingerprint(output_file)
        if output_after is None or output_after == job.get("output_before"):
            # A skipped/failed job must not claim an older file. Preserve any
            # existing record until this job demonstrably creates/changes output.
            continue
        try:
            relative = os.path.relpath(os.path.abspath(output_file), os.path.abspath(loot))
        except (OSError, ValueError):
            relative = output_file
        relative = str(relative).replace("\\", "/")
        record = {
            "host": job.get("host"),
            "tool": job.get("tool"),
            "parser": job.get("parser"),
            "output_file": relative,
            "command": job.get("command"),
            "status": job.get("state"),
        }
        existing[relative.lower()] = record

    payload = {"schema_version": 1, "records": list(existing.values())}
    write_text(manifest_path, json.dumps(payload, indent=2) + "\n")
    return manifest_path


def _print_run_plan(live: List[Dict[str, Any]]) -> None:
    print()
    print(bold("PathFinder Recon Plan", C.CYAN))
    print(color(f"  {len(live)} unauthenticated recon command(s) queued", C.GREEN))
    for host in _ordered_hosts(live):
        host_jobs = [x for x in live if x["host"] == host]
        print(color(f"\n  Host: {host}  ({len(host_jobs)} task(s))", C.BOLD + C.CYAN))
        for s in [x for x in live if x["host"] == host]:
            print(f"    {color(_fit_cell(s['tool'], TOOL_COL_WIDTH), C.BOLD)}  {color(s['group'], C.GREY)}")
            print(f"      {s['command']}")


def _fmt_elapsed(seconds: float) -> str:
    total = int(seconds)
    return f"{total // 60:02d}:{total % 60:02d}"


TOOL_COL_WIDTH = 22
HOST_COL_WIDTH = 15
STATE_COL_WIDTH = 14
DEFAULT_STATUS_WIDTH = 120


def _fit_cell(value: Any, width: int) -> str:
    text = str(value or "")
    if len(text) > width:
        return text[:max(0, width - 1)] + "~"
    return text.ljust(width)


def _clean_status_line(value: str) -> str:
    text = str(value or "")
    # Tools such as ffuf emit progress with carriage returns and ANSI/CSI
    # controls. If those escape codes leak into the live table they can clear or
    # move the terminal cursor, making the tool/host cells appear to vanish.
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", " ", text)
    text = re.sub(r"\x1b[@-Z\\-_]", " ", text)
    text = text.translate({ord(ch): " " for ch in "\r\n\t\b\f\v"})
    text = "".join(ch if (ch >= " " and ch != "\x7f") else " " for ch in text)
    return " ".join(text.split())


def _format_job_row(job: Dict[str, Any], now: float, width: int = DEFAULT_STATUS_WIDTH) -> str:
    state = job["state"]
    disp = {"skip:no-tool": "skip (no tool)", "skip:no-wordlist": "skip (no wl)"}.get(state, state)
    elapsed = _fmt_elapsed((job["end"] or now) - job["start"]) if job["start"] else "--:--"
    state_color = C.GREEN if state == "done" else C.YELLOW if state in ("starting", "running", "queued") else C.RED
    elapsed_width = 5
    base_width = 2 + TOOL_COL_WIDTH + 2 + HOST_COL_WIDTH + 2 + STATE_COL_WIDTH + 2 + elapsed_width
    marker = "> " if state in ("starting", "running") else "  "
    row = (
        f"{marker}{color(_fit_cell(job['tool'], TOOL_COL_WIDTH), C.BOLD)}"
        f"  {color(_fit_cell(job['host'], HOST_COL_WIDTH), C.CYAN)}"
        f"  {color(_fit_cell(disp, STATE_COL_WIDTH), state_color)}"
        f"  {color(elapsed, C.GREY)}"
    )
    if state == "running" and job["last"]:
        suffix = "  | "
        remaining = max(0, width - base_width - len(suffix))
        row += suffix + _fit_cell(_clean_status_line(job["last"]), remaining).rstrip()
    return row


class _LiveTable:
    """Minimal in-place multi-line renderer for a refreshing status table (TTY only)."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self.prev_lines = 0

    def render(self, lines: List[str]) -> None:
        if not self.enabled:
            return
        buf = ""
        if self.prev_lines:
            buf += f"\033[{self.prev_lines}A"  # cursor up to the top of the previous table
        for line in lines:
            buf += "\033[2K" + line + "\n"      # clear line, then redraw
        sys.stdout.write(buf)
        sys.stdout.flush()
        self.prev_lines = len(lines)


def _terminate_process(proc) -> None:
    """Terminate a subprocess and the tool behind the shell=True wrapper.

    POSIX: the child runs in its own session (see _run_worker), so signal the
    whole process group (SIGTERM, then SIGKILL). Windows: taskkill /T tears down
    the whole tree so the stdout pipe closes and the reader unblocks.
    """
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=5)
                return
            except Exception:
                pass
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True)
    except (ProcessLookupError, OSError):
        return
    except Exception:
        pass


def _command_with_pipefail(command: str,
                           os_name: Optional[str] = None,
                           bash_path: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """Run piped POSIX commands under bash pipefail so tee does not hide failures."""
    current_os = os_name or os.name
    if current_os != "posix" or "|" not in command:
        return command, None
    bash = bash_path if bash_path is not None else shutil.which("bash")
    if not bash:
        return command, None
    return f"set -o pipefail\n{command}", bash


def _run_worker(job: Dict[str, Any], lock: threading.Lock, tty: bool) -> None:
    with lock:
        if job.get("interrupted") or job.get("state") == "interrupted":
            job["state"] = "interrupted"
            job["end"] = time.time()
            return
        job["state"] = "running"
        job["start"] = time.time()
        job["last_output"] = job["start"]
    try:
        with open(job["logpath"], "w", encoding="utf-8", errors="replace") as logf:
            command, shell_executable = _command_with_pipefail(job["command"])
            # shell=True so redirections, pipes, and quoting work. On POSIX,
            # piped commands use bash pipefail so tee does not mask tool failures.
            # stdin=DEVNULL so a tool that prompts for input gets EOF instead of
            # blocking forever. On POSIX start_new_session gives the tool its own
            # process group so the idle-timeout can kill it (not just the shell).
            popen_kwargs = dict(
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, text=True, bufsize=1, errors="replace",
            )
            if shell_executable:
                popen_kwargs["executable"] = shell_executable
            if os.name == "posix":
                popen_kwargs["start_new_session"] = True
            proc = subprocess.Popen(command, **popen_kwargs)
            with lock:
                job["proc"] = proc
            # text mode uses universal newlines, so carriage-return progress lines
            # from tools like ffuf arrive as discrete lines we can tail.
            for line in proc.stdout:
                logf.write(line)
                stripped = line.strip()
                with lock:
                    job["last_output"] = time.time()
                    if stripped:
                        job["last"] = _clean_status_line(stripped)
            proc.wait()
            with lock:
                job["rc"] = proc.returncode
    except Exception as exc:
        with lock:
            job["rc"] = -1
            job["error"] = str(exc)
    with lock:
        job["end"] = time.time()
        if job.get("error"):
            job["state"] = "failed"
        elif job.get("interrupted"):
            job["state"] = "interrupted"
        elif job.get("timed_out"):
            job["state"] = "timed out"
        elif job.get("rc") == 0:
            job["state"] = "done"
        else:
            job["state"] = f"exit {job.get('rc')}"

    if not tty:
        elapsed = _fmt_elapsed(job["end"] - job["start"])
        if job["state"] == "failed":
            err(f"[fail] {job['tool']} ({job['host']}): {job.get('error')}")
        else:
            good(f"[{job['state']}] {job['tool']} ({job['host']}) in {elapsed}")


def run_suggestions(all_suggestions: List[Dict[str, Any]],
                    loot: str,
                    wordlist: str,
                    userlist: str,
                    idle_timeout: int = DEFAULT_RUN_IDLE_TIMEOUT) -> Optional[Dict[str, int]]:
    """Execute the live recon commands with one concurrency lane per host.

    Each host gets its own lane running up to PER_HOST_LANE tools at once; lanes
    run in parallel, so concurrency auto-scales with the number of hosts while no
    single host is ever hammered. Missing tools/wordlists are skipped before
    launch, a tool that produces no output for `idle_timeout` seconds is killed
    (a hang), and every tool's output is captured under <loot>/_logs/.
    """
    live = runnable_suggestions(all_suggestions)
    if not live:
        warn("No runnable (unauthenticated) commands to execute.")
        return None

    _print_run_plan(live)

    loot_path = Path(loot)
    logs_dir = loot_path / "_logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    # Create a per-host subdirectory (and its ldap/ subdir) for every host we'll write to.
    for host in {s["host"] for s in all_suggestions}:
        host_dir = loot_path / safe_name(host)
        (host_dir / "ldap").mkdir(parents=True, exist_ok=True)

    # Build job records and pre-skip missing tools / wordlists before launch.
    jobs: List[Dict[str, Any]] = []
    for idx, s in enumerate(live):
        binary = s["command"].split()[0]
        job: Dict[str, Any] = {
            "tool": s["tool"], "host": s["host"], "command": s["command"],
            "parser": s.get("parser"), "output_file": s.get("output_file") or None,
            "state": "queued", "last": "", "rc": None, "start": None, "end": None,
            "error": "", "proc": None, "timed_out": False, "interrupted": False, "last_output": None,
            "logpath": str(logs_dir / f"{safe_name(s['tool'])}_{safe_name(s['host'])}_{idx}.log"),
        }
        job["output_before"] = _output_fingerprint(job["output_file"])
        if shutil.which(binary) is None:
            job["state"] = "skip:no-tool"
        else:
            missing_dep = next(
                (dep for dep in (wordlist, userlist)
                 if dep and dep in s["command"] and not os.path.exists(dep)),
                None,
            )
            if missing_dep:
                job["state"] = "skip:no-wordlist"
        jobs.append(job)

    to_run = [j for j in jobs if not j["state"].startswith("skip")]
    tty = sys.stdout.isatty()
    renderer = _LiveTable(enabled=tty)
    lock = threading.Lock()

    # One explicit lane queue per host. We keep this scheduler visible in the
    # refresh loop instead of relying on ThreadPoolExecutor's private queue so a
    # freed slot is backfilled immediately and the table state stays honest.
    jobs_by_host: Dict[str, List[Dict[str, Any]]] = {}
    for j in to_run:
        jobs_by_host.setdefault(j["host"], []).append(j)
    pending_by_host: Dict[str, List[Dict[str, Any]]] = {
        host: list(host_jobs) for host, host_jobs in jobs_by_host.items()
    }
    worker_threads: List[threading.Thread] = []
    active_states = {"starting", "running"}

    def build_lines() -> List[str]:
        now = time.time()
        # Leave one spare column: some terminals wrap when a line exactly fills
        # the viewport, which makes the active tool row appear to vanish or smear.
        width = max(80, shutil.get_terminal_size((DEFAULT_STATUS_WIDTH, 20)).columns - 1)
        running = sum(1 for j in jobs if j["state"] in active_states)
        done = sum(1 for j in jobs if j["state"] == "done")
        skipped = sum(1 for j in jobs if j["state"].startswith("skip"))
        other = sum(1 for j in jobs if j["state"] in ("failed", "timed out", "interrupted") or j["state"].startswith("exit"))
        header = (f"Recon [{len(jobs_by_host)} host lane(s), {PER_HOST_LANE}/host]  "
                  f"{running} running  {done} done  {skipped} skipped  {other} other")
        lines = [bold(header, C.CYAN)]
        for j in jobs:
            lines.append(_format_job_row(j, now, width))
        return lines

    def enforce_idle_timeout():
        if idle_timeout <= 0:
            return
        now = time.time()
        for j in to_run:
            if j["state"] != "running" or j.get("timed_out"):
                continue
            proc, last = j.get("proc"), j.get("last_output")
            if proc is not None and last is not None and (now - last) > idle_timeout:
                j["timed_out"] = True  # worker labels the state once the process ends
                _terminate_process(proc)

    def fill_host_lanes() -> None:
        for host, pending in pending_by_host.items():
            while pending:
                with lock:
                    active_for_host = sum(1 for j in jobs_by_host[host] if j["state"] in active_states)
                    if active_for_host >= PER_HOST_LANE:
                        break
                    job = pending.pop(0)
                    if job.get("interrupted"):
                        job["state"] = "interrupted"
                        job["end"] = time.time()
                        continue
                    job["state"] = "starting"
                thread = threading.Thread(target=_run_worker, args=(job, lock, tty), daemon=False)
                worker_threads.append(thread)
                thread.start()

    print()
    if not tty:
        info(f"Running {len(to_run)} command(s) across {len(jobs_by_host)} host lane(s) "
             f"({PER_HOST_LANE}/host); output -> {logs_dir}")
        for j in jobs:
            if j["state"].startswith("skip"):
                warn(f"[skip] {j['tool']} ({j['host']}): {j['state'].split(':', 1)[1]}")

    interrupted = False
    try:
        fill_host_lanes()
        renderer.render(build_lines())
        while any(j["state"] in ("queued", "starting", "running") for j in to_run):
            enforce_idle_timeout()
            fill_host_lanes()
            renderer.render(build_lines())
            time.sleep(0.3)
        renderer.render(build_lines())
    except KeyboardInterrupt:
        interrupted = True
        warn("Interrupted; terminating active recon tools before leaving the run.")
        with lock:
            active = [j for j in to_run if j["state"] in active_states and j.get("proc") is not None]
            queued = [j for j in to_run if j["state"] in ("queued", "starting")
                      or (j["state"] == "running" and j.get("proc") is None)]
            for j in active:
                j["interrupted"] = True
            for j in queued:
                j["interrupted"] = True
                j["state"] = "interrupted"
                j["end"] = time.time()
        for j in active:
            _terminate_process(j["proc"])
        renderer.render(build_lines())
    finally:
        for thread in worker_threads:
            thread.join()

    ran = sum(1 for j in jobs if j["state"] == "done")
    skipped = sum(1 for j in jobs if j["state"].startswith("skip"))
    nonzero = sum(1 for j in jobs if j["state"].startswith("exit"))
    failed = sum(1 for j in jobs if j["state"] == "failed")
    timed_out = sum(1 for j in jobs if j["state"] == "timed out")
    interrupted_count = sum(1 for j in jobs if j["state"] == "interrupted")

    print()
    good(f"Recon complete: {ran} ran clean, {skipped} skipped, {nonzero} non-zero exit, "
         f"{failed} failed, {timed_out} timed out, {interrupted_count} interrupted")
    good(f"Per-tool logs: {logs_dir}")
    provenance_path = _write_pathfinder_provenance(loot, jobs)
    good(f"Discovery provenance: {provenance_path}")
    return {
        "ran": ran, "skipped": skipped, "nonzero": nonzero, "failed": failed,
        "timed_out": timed_out, "interrupted": interrupted_count if interrupted else 0,
    }


def run_pathfinder(pathfinder_path: str, loot: str,
                   top: int | None = None, min_likelihood: str | None = None,
                   show_all: bool = False,
                   hide_discovery: bool = False,
                   hide_findings: bool = False,
                   validate_credentials: bool = False,
                   target_host: str | None = None,
                   output_json: str | None = None,
                   verbose: int = 0,
                   max_vulns: int | None = None,
                   offline: bool = False,
                   skip_github: bool = False,
                   skip_searchsploit: bool = False,
                   github_cache: str | None = None,
                   no_color: bool = False,
                   oscp: bool = False) -> None:
    """Invoke PathFinder's scan mode on the loot directory."""
    pf = Path(pathfinder_path)
    if not (pf / "main" / "pathfinder.py").exists():
        err(f"PathFinder not found at '{pf}' (expected a sibling PathFinder/ with main/pathfinder.py).")
        return

    loot_abs = os.path.abspath(loot)
    # Save the prioritized findings next to (not inside) the loot dir, so they
    # feed PathFinder's iterative -i reload/append workflow and never get
    # re-ingested on a subsequent scan of the loot tree.
    findings_path = os.path.abspath(output_json) if output_json else os.path.join(os.path.dirname(loot_abs), "findings.json")
    info(f"Launching PathFinder on {loot_abs} (findings -> {findings_path})")
    cmd = [sys.executable, "-m", "main.pathfinder", "scan", loot_abs, "-o", findings_path]
    if target_host:
        cmd.extend(["--target-host", target_host])
    if verbose:
        cmd.extend(["-v"] * verbose)
    if max_vulns is not None:
        cmd.extend(["--max-vulns", str(max_vulns)])
    if offline:
        cmd.append("--offline")
    if skip_github:
        cmd.append("--skip-github")
    if skip_searchsploit:
        cmd.append("--skip-searchsploit")
    if github_cache:
        cmd.extend(["--github-cache", github_cache])
    if no_color:
        cmd.append("--no-color")
    if oscp:
        cmd.append("--oscp")
    if top is not None:
        cmd.extend(["--top", str(top)])
    if min_likelihood:
        cmd.extend(["--min-likelihood", min_likelihood])
    if show_all:
        cmd.append("--show-all")
    if hide_discovery:
        cmd.append("--hide-discovery")
    if hide_findings:
        cmd.append("--hide-findings")
    if validate_credentials:
        cmd.append("--validate-credentials")
    try:
        subprocess.run(cmd, cwd=str(pf))
    except Exception as exc:
        err(f"PathFinder invocation failed: {exc}")


# =========================
# CLI
# =========================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lightweight nmap wrapper for one-shot initial pentest enumeration."
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="IPs, CIDRs, ranges, or localhost",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Concurrent stage-1 TCP discovery scans (default: 10)",
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Run an additional UDP top-ports scan",
    )
    parser.add_argument(
        "--udp-top-ports",
        type=int,
        default=20,
        help="Top UDP ports to scan when --udp is enabled (default: 20)",
    )
    parser.add_argument(
        "--ports",
        help="Comma-separated TCP ports and ranges to scan instead of a full-port discovery pass (example: 80,443,8000-8010)",
    )
    parser.add_argument(
        "--llm-endpoint",
        action="store_true",
        help="Quick, read-only peek: list discovered OpenAPI endpoints on LLM/API-like services",
    )
    parser.add_argument(
        "--timing",
        choices=["T1", "T2", "T3", "T4", "T5"],
        default="T4",
        help="Nmap timing template for stage-1 TCP port discovery only (default: T4)",
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Create per-host folders and save XML/reports/CSV",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in terminal output",
    )
    parser.add_argument(
        "--outdir",
        default="scan_results",
        help="Base output directory when --save is used (default: scan_results)",
    )
    parser.add_argument(
        "--pathfinder-suggest",
        dest="pathfinder_suggest",
        action="store_true",
        help="Print the follow-up enumeration commands for PathFinder to consume, "
             "and write a runnable recon script",
    )
    parser.add_argument(
        "--pathfinder",
        action="store_true",
        help="Run unauthenticated recon commands (skipping missing tools), then "
             "hand results to PathFinder. Full AI enumeration is already on by default.",
    )
    parser.add_argument(
        "--power",
        action="store_true",
        help="With --pathfinder-suggest/--pathfinder, add heavier web checks: nuclei.",
    )
    parser.add_argument(
        "--run-timeout",
        type=int,
        default=DEFAULT_RUN_IDLE_TIMEOUT,
        help=f"With --pathfinder, kill a tool that produces no output for this many seconds "
             f"(a hang); 0 disables (default: {DEFAULT_RUN_IDLE_TIMEOUT})",
    )
    parser.add_argument(
        "--scan-timeout",
        type=int,
        default=DEFAULT_SCAN_TIMEOUT,
        help=f"Wall-clock ceiling (seconds) for a single nmap invocation so one slow/"
             f"filtered host can't hang the scan; 0 disables (default: {DEFAULT_SCAN_TIMEOUT})",
    )
    parser.add_argument(
        "--loot-dir",
        default=LOOT_DIR,
        help=f"Directory for loot / PathFinder handoff (default: {LOOT_DIR}). Use a "
             f"fresh dir per engagement so PathFinder never mixes current and stale data",
    )
    parser.add_argument(
        "--top",
        type=int,
        help="With --pathfinder, pass through to PathFinder: max grouped attack-path leads to display "
             "(PathFinder default: 20; 0 = all groups)",
    )
    parser.add_argument(
        "--min-likelihood",
        choices=["low", "medium", "high"],
        help="With --pathfinder, pass through to PathFinder: only display attack paths at or above "
             "this triage likelihood (PathFinder default: low)",
    )
    parser.add_argument(
        "--show-all",
        action="store_true",
        help="With --pathfinder, pass through to PathFinder: display every synthesized attack path "
             "instead of grouped triage output",
    )
    parser.add_argument(
        "--hide-discovery",
        action="store_true",
        help="With --pathfinder, hide discovery tool and command provenance from findings and attack paths",
    )
    parser.add_argument(
        "--hide-findings",
        action="store_true",
        help="With --pathfinder, hide PathFinder's prioritized findings list",
    )
    parser.add_argument(
        "--validate-credentials",
        action="store_true",
        help="With --pathfinder, actively test resolved credential-reuse login actions sequentially",
    )
    parser.add_argument(
        "--target-host",
        help="With --pathfinder, pass through to PathFinder scan. Usually unnecessary because "
             "one-shot-enum writes per-host loot directories.",
    )
    parser.add_argument(
        "-o", "--output-json",
        help="With --pathfinder, pass through to PathFinder: findings JSON path "
             "(default: findings.json next to the loot dir)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="With --pathfinder, pass through to PathFinder verbosity (-v, -vv)",
    )
    parser.add_argument(
        "--max-vulns",
        type=int,
        help="With --pathfinder, pass through to PathFinder: max EDB/GitHub exploits to display "
             "(PathFinder default: 10)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="With --pathfinder, pass through to PathFinder: disable all external enrichment lookups",
    )
    parser.add_argument(
        "--skip-github",
        action="store_true",
        help="With --pathfinder, pass through to PathFinder: skip GitHub exploit enrichment",
    )
    parser.add_argument(
        "--skip-searchsploit",
        action="store_true",
        help="With --pathfinder, pass through to PathFinder: skip Searchsploit enrichment",
    )
    parser.add_argument(
        "--github-cache",
        help="With --pathfinder, pass through to PathFinder: GitHub lookup cache JSON path",
    )
    parser.add_argument(
        "--oscp",
        action="store_true",
        help="With --pathfinder, pass through to PathFinder: OSCP exam profile",
    )
    args = parser.parse_args()
    if args.run_timeout < 0:
        parser.error("--run-timeout must be >= 0.")
    if args.scan_timeout < 0:
        parser.error("--scan-timeout must be >= 0.")
    if args.top is not None and args.top < 0:
        parser.error("--top must be >= 0.")
    if args.max_vulns is not None and args.max_vulns < 0:
        parser.error("--max-vulns must be >= 0.")
    if args.pathfinder_suggest and args.pathfinder:
        parser.error("Use either --pathfinder-suggest or --pathfinder, not both.")
    used_pathfinder_only = []
    if args.target_host:
        used_pathfinder_only.append("--target-host")
    if args.output_json:
        used_pathfinder_only.append("--output-json")
    if args.verbose:
        used_pathfinder_only.append("-v/--verbose")
    if args.max_vulns is not None:
        used_pathfinder_only.append("--max-vulns")
    if args.offline:
        used_pathfinder_only.append("--offline")
    if args.skip_github:
        used_pathfinder_only.append("--skip-github")
    if args.skip_searchsploit:
        used_pathfinder_only.append("--skip-searchsploit")
    if args.github_cache:
        used_pathfinder_only.append("--github-cache")
    if args.oscp:
        used_pathfinder_only.append("--oscp")
    if args.show_all:
        used_pathfinder_only.append("--show-all")
    if args.hide_discovery:
        used_pathfinder_only.append("--hide-discovery")
    if args.hide_findings:
        used_pathfinder_only.append("--hide-findings")
    if args.validate_credentials:
        used_pathfinder_only.append("--validate-credentials")
    if args.top is not None:
        used_pathfinder_only.append("--top")
    if args.min_likelihood:
        used_pathfinder_only.append("--min-likelihood")
    if used_pathfinder_only and not args.pathfinder:
        parser.error(f"{', '.join(used_pathfinder_only)} only apply with --pathfinder.")
    if any(is_localhost_target(target) for target in args.targets):
        normalized = {target.strip().lower() for target in args.targets}
        if len(normalized) > 1:
            parser.error("When using localhost, run it by itself as the target.")
    return args


def _llm_enum_options(args: argparse.Namespace, use_local_fallback: bool = False) -> Optional[Dict[str, bool]]:
    if getattr(args, "llm_endpoint", False):
        return {
            "endpoint_only": True,
            "probe_all_http": use_local_fallback,
            "ai_paths_mode": False,
            "active": False,
        }
    return {
        "endpoint_only": False,
        "probe_all_http": True,
        "ai_paths_mode": True,
        "active": True,
    }


# =========================
# Main
# =========================

def main() -> None:
    global NMAP_SCAN_TIMEOUT
    args = parse_args()
    NMAP_SCAN_TIMEOUT = args.scan_timeout
    if args.no_color:
        set_color_mode(False)

    # Loot directory (default "loot") is chosen once here and used for every handoff.
    global LOOT_DIR
    LOOT_DIR = args.loot_dir

    try:
        targets = normalize_targets(args.targets)
    except ValueError as exc:
        err(str(exc))
        sys.exit(1)

    try:
        selected_tcp_ports = parse_port_spec(args.ports) if args.ports else []
    except ValueError as exc:
        err(str(exc))
        sys.exit(1)

    if not targets:
        err("No valid targets supplied.")
        sys.exit(1)

    # With a handoff to PathFinder, flag stale host data left in the loot dir.
    if args.pathfinder_suggest or args.pathfinder:
        warn_stale_loot(LOOT_DIR, targets)

    has_nmap = nmap_installed()
    use_local_fallback = not has_nmap and len(targets) == 1 and is_localhost_target(targets[0])

    if not has_nmap and not use_local_fallback:
        err("nmap not found in PATH. Install nmap, or run a localhost-only scan to use the built-in fallback.")
        sys.exit(1)
    if use_local_fallback:
        warn("nmap not found in PATH. Using localhost-only Python fallback mode.")

    llm_options = _llm_enum_options(args, use_local_fallback)

    base_outdir: Optional[Path] = None
    target_dirs: Dict[str, Optional[Path]] = {target: None for target in targets}

    if args.save:
        base_outdir = Path(args.outdir)
        base_outdir.mkdir(parents=True, exist_ok=True)
        for target in targets:
            host_dir = base_outdir / safe_name(target)
            host_dir.mkdir(parents=True, exist_ok=True)
            target_dirs[target] = host_dir

    good(f"Targets queued: {len(targets)}")
    info(f"Scan engine: {'python localhost fallback' if use_local_fallback else 'nmap'}")
    if use_local_fallback:
        info(f"Stage-1 threads: localhost worker pool up to {LOCALHOST_SCAN_WORKERS}")
        info("Stage-1 timing: python fallback")
        info("Host fingerprint: local platform fingerprint via Python standard library")
        if selected_tcp_ports:
            info(f"Stage-1 TCP port scope: {args.ports}")
        else:
            info("Stage-1 TCP port scope: full port range")
        info("Service enum timing: python fallback")
    else:
        info(f"Stage-1 threads: {args.threads}")
        info(f"Stage-1 timing: {args.timing}")
        if selected_tcp_ports:
            info("Host fingerprint: best effort OS detection on the selected TCP ports before -Pn fallback")
            info(f"Stage-1 TCP port scope: {args.ports}")
        else:
            info(f"Host fingerprint: best effort OS detection on top {HOST_FINGERPRINT_TOP_PORTS} ports before -Pn fallback")
            info("Stage-1 TCP port scope: full port range")
        info("Service enum timing: T3")
    if args.udp:
        if use_local_fallback:
            warn("UDP requested, but UDP scanning requires nmap; skipping UDP in localhost fallback mode")
        else:
            info(f"UDP enabled: top {args.udp_top_ports} ports (timing: T3)")
    if args.llm_endpoint:
        info("AI enumeration mode: quick OpenAPI peek only (--llm-endpoint)")
    else:
        info("AI enumeration mode: full rich probes + read-only MCP/A2A confirmation")
    info(f"Save output: {'yes' if args.save else 'no'}")
    if args.save and base_outdir:
        info(f"Output directory: {base_outdir}")
    print()

    if selected_tcp_ports:
        good("Starting targeted TCP discovery scans...")
    else:
        good("Starting TCP full-port discovery scans...")
    stage1_results: Dict[str, Dict] = {}

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        if use_local_fallback:
            future_map = {
                executor.submit(
                    localhost_tcp_discovery_scan,
                    target,
                    target_dirs[target],
                    selected_tcp_ports or None,
                ): target
                for target in targets
            }
        else:
            future_map = {
                executor.submit(
                    tcp_discovery_scan,
                    target,
                    target_dirs[target],
                    args.timing,
                    selected_tcp_ports or None,
                ): target
                for target in targets
            }

        for future in as_completed(future_map):
            target = future_map[future]
            try:
                result = future.result()
                stage1_results[target] = result
                open_ports = result.get("open_ports", [])
                if open_ports:
                    good(f"{target}: open TCP ports -> {','.join(map(str, open_ports))}")
                else:
                    warn(f"{target}: no open TCP ports found")
            except Exception as exc:
                err(f"{target}: {exc}")
                stage1_results[target] = {
                    "target": target,
                    "ip": target,
                    "hostname": "",
                    "extra": {},
                    "open_ports": [],
                    "error": str(exc),
                }

    print()
    good("Starting targeted TCP service scans...")
    print()

    csv_rows: List[Dict[str, str]] = []
    all_suggestions: List[Dict[str, Any]] = []

    for idx, target in enumerate(targets, start=1):
        print(color(f"[{idx}/{len(targets)}] {target}", C.BOLD))

        host_dir = target_dirs[target]
        s1 = stage1_results.get(target, {})
        tcp_open_ports = s1.get("open_ports", [])

        ip_addr = s1.get("ip", target)
        hostname = s1.get("hostname", "")
        extra: Dict[str, str] = s1.get("extra", {})
        tcp_services: List[Service] = []
        udp_services: List[Service] = []

        # Pin one host identity for this iteration so the loot subdir is consistent
        # across the nmap XML and every suggested tool output.
        loot_host = ip_addr
        loot_xml_dir = None
        if (args.pathfinder_suggest or args.pathfinder) and not use_local_fallback:
            loot_xml_dir = Path(LOOT_DIR) / safe_name(loot_host)

        if tcp_open_ports:
            try:
                tcp_result = (
                    localhost_tcp_service_scan(target, tcp_open_ports, host_dir)
                    if use_local_fallback
                    else tcp_service_scan(target, tcp_open_ports, host_dir, loot_xml_dir=loot_xml_dir)
                )
                ip_addr = tcp_result.get("ip", ip_addr)
                hostname = tcp_result.get("hostname", hostname)
                extra = merge_extra_info(extra, tcp_result.get("extra", {}))
                tcp_services = tcp_result.get("services", [])
                if llm_options:
                    try:
                        run_llm_enumeration(target, tcp_services, **llm_options)
                    except Exception as exc:
                        err(f"{target}: LLM/API enum failed: {exc}")
            except Exception as exc:
                err(f"{target}: TCP service scan failed: {exc}")
        else:
            warn(f"{target}: skipping TCP service scan because no TCP ports were discovered")

        if args.udp and not use_local_fallback:
            try:
                info(f"{target}: running UDP top-ports scan")
                udp_result = udp_scan(target, args.udp_top_ports, host_dir)
                udp_services = udp_result.get("udp_services", [])
            except Exception as exc:
                err(f"{target}: UDP scan failed: {exc}")

        print_host_summary(ip_addr, hostname, extra, tcp_services, udp_services)

        if args.pathfinder_suggest or args.pathfinder:
            # Full AI enumeration is handed to PathFinder-oriented loot for both
            # planning and live runs. --llm-endpoint intentionally stays a quick
            # terminal peek and does not write AI surface loot.
            if not args.llm_endpoint:
                for svc in tcp_services:
                    written_llm = write_llm_enum_loot(
                        loot_host, svc, LOOT_DIR,
                        discovery_command=shlex.join([sys.executable, *sys.argv]),
                    )
                    if written_llm:
                        good(f"AI surfaces -> {written_llm}")
            host_suggestions = suggest_for_host(
                loot_host, tcp_services, udp_services,
                LOOT_DIR, DEFAULT_WEB_WORDLIST, DEFAULT_USER_WORDLIST,
                power=args.power,
            )
            if args.pathfinder_suggest:
                # Use the same pinned host the loot paths are keyed on.
                print_suggestions(loot_host, host_suggestions)
            all_suggestions.extend(host_suggestions)

        if args.save and host_dir:
            write_host_report(host_dir, ip_addr, hostname, extra, tcp_services, udp_services)

        for svc in tcp_services:
            csv_rows.append({
                "ip": ip_addr,
                "hostname": hostname,
                "protocol": svc["protocol"],
                "port": svc["port"],
                "service": svc["service"],
                "product": svc["product"],
                "version": svc["version"],
                "extrainfo": svc["extrainfo"],
                "banner": service_banner(svc),
            })

        for svc in udp_services:
            csv_rows.append({
                "ip": ip_addr,
                "hostname": hostname,
                "protocol": svc["protocol"],
                "port": svc["port"],
                "service": svc["service"],
                "product": svc["product"],
                "version": svc["version"],
                "extrainfo": svc["extrainfo"],
                "banner": service_banner(svc),
            })

    if args.save and base_outdir:
        csv_path = base_outdir / "services_summary.csv"
        write_csv_summary(csv_path, csv_rows)
        good(f"Done. Summary CSV: {csv_path}")
        good("Per-host reports and raw XML saved under the output directory.")
    else:
        good("Done.")

    if args.pathfinder_suggest:
        if all_suggestions:
            script_dir = base_outdir if (args.save and base_outdir) else Path(".")
            try:
                written = write_recon_scripts(script_dir, all_suggestions, LOOT_DIR)
                for path in written:
                    good(f"Recon script written: {path}")
                good(f"Next: run the script, then `{PATHFINDER_SCAN_CMD} {LOOT_DIR}/`")
            except OSError as exc:
                err(f"Could not write recon script: {exc}")

    if args.pathfinder:
        run_result = None
        if all_suggestions:
            run_result = run_suggestions(
                all_suggestions, LOOT_DIR, DEFAULT_WEB_WORDLIST, DEFAULT_USER_WORDLIST,
                idle_timeout=args.run_timeout,
            )
        else:
            warn("--pathfinder: no recon-tool suggestions generated from discovered services; continuing to PathFinder.")
        if run_result and run_result.get("interrupted"):
            warn("--pathfinder interrupted: skipping PathFinder analysis of partial recon loot.")
            return
        # Always analyse with PathFinder; --pathfinder may have produced AI surface loot
        # even when no extra recon tools were runnable.
        pathfinder_path = str(Path(__file__).resolve().parent.parent / "PathFinder")
        run_pathfinder(
            pathfinder_path, LOOT_DIR,
            top=args.top,
            min_likelihood=args.min_likelihood,
            show_all=args.show_all,
            hide_discovery=args.hide_discovery,
            hide_findings=args.hide_findings,
            validate_credentials=args.validate_credentials,
            target_host=args.target_host,
            output_json=args.output_json,
            verbose=args.verbose,
            max_vulns=args.max_vulns,
            offline=args.offline,
            skip_github=args.skip_github,
            skip_searchsploit=args.skip_searchsploit,
            github_cache=args.github_cache,
            no_color=args.no_color,
            oscp=args.oscp,
        )


if __name__ == "__main__":
    main()
