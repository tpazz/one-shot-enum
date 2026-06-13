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
- Optional LLM/API enum:
    - With --llm-endpoint, detect LLM/API-like services and list OpenAPI endpoints
    - With --llm-full, also probe useful config/model/chat paths
    - With --hello, send a test prompt to /chat when discovered
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
import shutil
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
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
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


def info(msg: str) -> None:
    print(color("[*]", C.BLUE), msg)


def good(msg: str) -> None:
    print(color("[+]", C.GREEN), msg)


def warn(msg: str) -> None:
    print(color("[!]", C.YELLOW), msg)


def err(msg: str) -> None:
    print(color("[-]", C.RED), msg, file=sys.stderr)


def progress(msg: str) -> None:
    if sys.stdout.isatty():
        print(f"\r{color('[>]', C.CYAN)} {msg:<120}", end="", flush=True)
    else:
        print(f"{color('[>]', C.CYAN)} {msg}")


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

    while proc.poll() is None or not q.empty():
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
LLM_CHAT_MESSAGE = "Hello, what can you help me with and what are your capabilities?"
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
)
OPENAPI_CANDIDATE_PATHS = (
    "/openapi.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/swagger.json",
)
LLM_PROBE_PATHS = (
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/ai-plugin.json",
    "/.well-known/agent.json",
    "/agent.json",
    "/ai-plugin.json",
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/docs",
    "/redoc",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/chat",
    "/chat/",
    "/v1/models",
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    "/api/tags",
    "/api/generate",
    "/api/chat",
    "/mcp",
    "/sse",
    "/messages",
    "/health",
    "/healthz",
    "/ready",
    "/readyz",
    "/metrics",
    "/version",
    "/config",
    "/config.json",
)


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
                 timeout: int = HTTP_TIMEOUT_SECONDS) -> Dict[str, Any]:
    data = None
    headers = {
        "Accept": "application/json, text/plain;q=0.9, */*;q=0.8",
        "User-Agent": "one-shot-enum/llm-enum",
    }

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body_bytes = response.read()
            status = response.getcode()
            content_type = response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read()
        status = exc.code
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {
            "ok": False,
            "status": None,
            "content_type": "",
            "text": "",
            "json": None,
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
        "error": "",
    }


def format_response_body(response: Dict[str, Any]) -> str:
    if response.get("json") is not None:
        return truncate_text(json.dumps(response["json"], indent=2, sort_keys=True))
    return truncate_text(response.get("text", "").strip())


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
    return 200 <= status < 400 or status in (401, 403, 405)


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
                          send_hello: bool = False,
                          endpoint_only: bool = False) -> Dict[str, Any]:
    base_url = service_base_url(target, service)
    openapi_url = f"{base_url}{OPENAPI_CANDIDATE_PATHS[0]}"
    openapi_response = http_request(openapi_url)

    result: Dict[str, Any] = {
        "base_url": base_url,
        "endpoint_only": endpoint_only,
        "openapi_url": "",
        "openapi_status": None,
        "openapi_error": "",
        "endpoints": [],
        "probe_count": len(LLM_PROBE_PATHS),
        "probe_hits": [],
        "chat_path": "",
        "chat_attempted": False,
        "chat_status": None,
        "chat_error": "",
        "chat_response": "",
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
        return result

    result["probe_hits"] = probe_llm_paths(base_url)

    chat_path = next(
        (
            endpoint["path"]
            for endpoint in result["endpoints"]
            if endpoint["path"].rstrip("/") == "/chat"
        ),
        "",
    )
    if not chat_path:
        chat_path = next(
            (
                hit["path"]
                for hit in result["probe_hits"]
                if hit["path"].rstrip("/") == "/chat"
            ),
            "",
        )

    result["chat_path"] = chat_path

    if chat_path and send_hello:
        chat_url = f"{base_url}{chat_path}"
        chat_response = http_request(
            chat_url,
            method="POST",
            payload={"message": LLM_CHAT_MESSAGE},
        )
        result["chat_attempted"] = True
        result["chat_url"] = chat_url
        result["chat_status"] = chat_response.get("status")
        result["chat_error"] = chat_response.get("error", "")
        result["chat_response"] = format_response_body(chat_response)

    return result


def run_llm_enumeration(target: str,
                        tcp_services: List[Service],
                        send_hello: bool = False,
                        endpoint_only: bool = False,
                        probe_all_http: bool = False) -> None:
    for service in tcp_services:
        if not resembles_llm_service(service) and not (probe_all_http and is_http_like_service(service)):
            continue

        port = service.get("port", "")
        action = "checking OpenAPI endpoints" if endpoint_only else "probing endpoints and common paths"
        info(f"{target}:{port}: LLM/API-like service found; {action}")
        service["llm_enum"] = enumerate_llm_service(
            target,
            service,
            send_hello=send_hello,
            endpoint_only=endpoint_only,
        )


def llm_enum_lines(llm_enum: Dict[str, Any]) -> List[str]:
    endpoint_only = bool(llm_enum.get("endpoint_only"))
    lines: List[str] = ["LLM/API endpoint enum:" if endpoint_only else "LLM/API enum:"]
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

    if llm_enum.get("chat_attempted"):
        chat_status = llm_enum.get("chat_status")
        chat_status_text = f"status {chat_status}" if chat_status is not None else "no status"
        chat_path = llm_enum.get("chat_path", "/chat")
        lines.append(f"  POST {chat_path}: {chat_status_text}")
        if llm_enum.get("chat_error"):
            lines.append(f"    Error: {llm_enum['chat_error']}")
        else:
            response_body = llm_enum.get("chat_response", "").strip()
            lines.append("    Response:")
            if response_body:
                lines.extend(f"      {line}" for line in response_body.splitlines())
            else:
                lines.append("      (empty response)")
    elif llm_enum.get("chat_path"):
        lines.append(f"  POST {llm_enum['chat_path']}: discovered; use --hello to send test prompt")
    else:
        lines.append("  POST /chat: not found in OpenAPI or path probes")

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


def tcp_service_scan(target: str, ports: List[int], outdir: Optional[Path]) -> Dict:
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
    print("=" * 88)
    host_line = f"Host: {ip_addr}"
    if hostname:
        host_line += f" ({hostname})"
    print(color(host_line, C.BOLD))

    if extra.get("mac"):
        mac_line = f"MAC: {extra['mac']}"
        if extra.get("vendor"):
            mac_line += f" [{extra['vendor']}]"
        print(mac_line)

    if extra.get("lastboot"):
        print(f"Last boot: {extra['lastboot']}")

    if extra.get("os_guess"):
        print(f"OS guess: {extra['os_guess']}")

    print("-" * 88)

    if tcp_services:
        print(color("TCP", C.CYAN))
        print(f"{'PORT':<10}{'PROTO':<8}{'SERVICE INFO'}")
        print("-" * 88)
        for svc in tcp_services:
            print(f"{svc['port']:<10}{svc['protocol']:<8}{service_banner(svc)}")
            if svc.get("llm_enum"):
                for line in llm_enum_lines(svc["llm_enum"]):
                    print(f"{'':<18}{line}")
            if svc["scripts"]:
                for sline in svc["scripts"].splitlines():
                    print(f"{'':<18}└─ {sline}")
    else:
        print("No open TCP ports discovered.")

    if udp_services:
        print("-" * 88)
        print(color("UDP", C.CYAN))
        print(f"{'PORT':<10}{'PROTO':<8}{'SERVICE INFO'}")
        print("-" * 88)
        for svc in udp_services:
            print(f"{svc['port']:<10}{svc['protocol']:<8}{service_banner(svc)}")
            if svc["scripts"]:
                for sline in svc["scripts"].splitlines():
                    print(f"{'':<18}└─ {sline}")

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
#   one-shot-enum <target> --suggest   ->   run commands into the loot dir
#                                       ->   pathfinder scan <loot>/

LOOT_DIR = "loot"
DEFAULT_WEB_WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
DEFAULT_USER_WORDLIST = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
PATHFINDER_SCAN_CMD = "python3 -m main.pathfinder scan"

WEB_PORTS = {80, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8180,
             8443, 8444, 8800, 8888, 9000, 9090, 9443}
WEB_HTTPS_PORTS = {443, 8443, 8444, 9443, 2083, 2087, 2096}
SMB_PORTS = {139, 445}
LDAP_PORTS = {389, 636, 3268, 3269}
KERBEROS_PORTS = {88}
SNMP_PORTS = {161}

DOMAIN_PLACEHOLDER = "<domain>"
USER_PLACEHOLDER = "<user>"
PASS_PLACEHOLDER = "<pass>"


def _suggestion(host: str, group: str, tool: str, command: str, parser: str,
                pending: bool = False, gated: bool = False, shell: str = "bash",
                note: str = "") -> Dict[str, Any]:
    return {
        "host": host, "group": group, "tool": tool, "command": command,
        "parser": parser, "pending": pending, "gated": gated, "shell": shell,
        "note": note,
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


def _web_suggestions(host: str, service: Service, loot: str, wordlist: str) -> List[Dict[str, Any]]:
    scheme = _web_scheme(service)
    port = _svc_port(service)
    base = f"{scheme}://{host}:{port}"
    group = f"web {scheme}:{port}"
    k = " -k" if scheme == "https" else ""
    out = [
        _suggestion(host, group, "whatweb",
                    f"whatweb -a3 {base} --log-json={loot}/whatweb_{port}.json", "whatweb_json"),
        _suggestion(host, group, "gobuster",
                    f"gobuster dir -u {base} -w {wordlist}{k} -o {loot}/gobuster_{port}.txt", "gobuster_txt"),
        _suggestion(host, group, "ffuf",
                    f"ffuf -u {base}/FUZZ -w {wordlist}{k} -of json -o {loot}/ffuf_{port}.json",
                    "ffuf_json"),
        _suggestion(host, group, "nikto",
                    f"nikto -h {base} -Format json -o {loot}/nikto_{port}.json", "nikto_json"),
        _suggestion(host, group, "nuclei",
                    f"nuclei -u {base} -jsonl -o {loot}/nuclei_{port}.jsonl", "nuclei_jsonl"),
    ]
    if _looks_wordpress(service):
        out.append(_suggestion(host, group, "wpscan",
                   f"wpscan --url {base} --format json -o {loot}/wpscan_{port}.json --disable-tls-checks",
                   "wpscan_json"))
    return out


def _smb_suggestions(host: str, loot: str) -> List[Dict[str, Any]]:
    tag = safe_name(host)
    return [
        _suggestion(host, "smb", "enum4linux-ng",
                    f"enum4linux-ng -A -oJ {loot}/enum4linux_{tag} {host}", "enum4linux_json"),
        _suggestion(host, "smb", "smbmap",
                    f"smbmap -H {host} -u guest -p '' > {loot}/smbmap_{tag}.txt", "smbmap_txt"),
        _suggestion(host, "smb", "netexec",
                    f"nxc smb {host} --shares --users --log {loot}/nxc_{tag}.log",
                    "netexec_log"),
    ]


def _snmp_suggestions(host: str, loot: str) -> List[Dict[str, Any]]:
    return [
        _suggestion(host, "snmp", "snmp-check",
                    f"snmp-check {host} -c public > {loot}/snmp_{safe_name(host)}.txt", "snmp_txt"),
    ]


def _ad_suggestions(host: str, loot: str, userlist: str) -> List[Dict[str, Any]]:
    dom, user, pw = DOMAIN_PLACEHOLDER, USER_PLACEHOLDER, PASS_PLACEHOLDER
    return [
        _suggestion(host, "ad kerberos", "kerbrute",
                    f"kerbrute userenum -d {dom} --dc {host} {userlist} -o {loot}/kerbrute.txt",
                    "kerbrute_txt"),
        _suggestion(host, "ad kerberos", "impacket-GetNPUsers",
                    f"impacket-GetNPUsers {dom}/ -dc-ip {host} -usersfile {userlist} "
                    f"-format hashcat -outputfile {loot}/getnpusers.txt", "getnpusers_hashes"),
        _suggestion(host, "ad (needs creds)", "ldapdomaindump",
                    f"ldapdomaindump -u '{dom}\\{user}' -p '{pw}' {host} -o {loot}/ldap/",
                    "ldapdomaindump_dir", gated=True),
        _suggestion(host, "ad (needs creds)", "impacket-GetUserSPNs",
                    f"impacket-GetUserSPNs {dom}/{user}:{pw} -dc-ip {host} -request "
                    f"-outputfile {loot}/getuserspns.txt", "getuserspns_hashes", gated=True),
        _suggestion(host, "ad (needs creds)", "certipy",
                    f"certipy find -u {user}@{dom} -p '{pw}' -dc-ip {host} -json -output {loot}/certipy",
                    "certipy_json", gated=True),
        _suggestion(host, "ad (needs creds)", "impacket-secretsdump",
                    f"impacket-secretsdump {dom}/{user}:{pw}@{host} | tee {loot}/secretsdump.txt",
                    "secretsdump_txt", gated=True),
    ]


def _post_foothold_suggestions(host: str, loot: str) -> List[Dict[str, Any]]:
    tag = safe_name(host)
    return [
        _suggestion(host, "post-foothold (linux)", "linpeas",
                    f"./linpeas.sh | tee {loot}/linpeas_{tag}.txt", "linpeas_txt", gated=True),
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
                     userlist: str) -> List[Dict[str, Any]]:
    suggestions: List[Dict[str, Any]] = []
    has_smb = False
    has_ad = False
    has_snmp = False

    for service in tcp_services:
        port = _svc_port(service)
        if _is_web_service(service):
            suggestions.extend(_web_suggestions(host, service, loot, wordlist))
        if _svc_name(service) in {"microsoft-ds", "netbios-ssn", "smb"} or port in SMB_PORTS:
            has_smb = True
        if "ldap" in _svc_name(service) or "kerberos" in _svc_name(service) \
                or port in LDAP_PORTS or port in KERBEROS_PORTS:
            has_ad = True

    for service in list(udp_services) + list(tcp_services):
        if "snmp" in _svc_name(service) or _svc_port(service) in SNMP_PORTS:
            has_snmp = True

    if has_smb:
        suggestions.extend(_smb_suggestions(host, loot))
    if has_snmp:
        suggestions.extend(_snmp_suggestions(host, loot))
    if has_ad:
        suggestions.extend(_ad_suggestions(host, loot, userlist))
    suggestions.extend(_post_foothold_suggestions(host, loot))

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
    if s["note"]:
        notes.append(s["note"])
    line = f"{s['command']}   # {'; '.join(notes)}"
    # Gated commands (need creds or a foothold) are emitted commented-out so the
    # script never runs anything unattended that depends on placeholders.
    return f"# {line}" if s["gated"] else line


def write_recon_scripts(outdir: Path,
                        all_suggestions: List[Dict[str, Any]],
                        loot: str) -> List[Path]:
    hosts: List[str] = []
    for s in all_suggestions:
        if s["host"] not in hosts:
            hosts.append(s["host"])

    bash_lines = [
        "#!/usr/bin/env bash",
        "# Generated by one-shot-enum --suggest. Review before running.",
        "# Live lines are unauthenticated recon; commented lines need creds/a foothold.",
        "set -u",
        f"mkdir -p {loot} {loot}/ldap",
        "",
    ]
    ps_lines = [
        "# Generated by one-shot-enum --suggest. Run these on the target after a foothold.",
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
    return [s for s in all_suggestions if not s["gated"] and s["shell"] == "bash"]


def _print_run_plan(live: List[Dict[str, Any]]) -> None:
    print(color(f"\nPlan: {len(live)} unauthenticated recon command(s)", C.BOLD))
    for host in _ordered_hosts(live):
        print(color(f"  {host}", C.CYAN))
        for s in [x for x in live if x["host"] == host]:
            print(f"    {s['tool']:<16} {s['command']}")


def _fmt_elapsed(seconds: float) -> str:
    total = int(seconds)
    return f"{total // 60:02d}:{total % 60:02d}"


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


def _run_worker(job: Dict[str, Any], lock: threading.Lock, tty: bool) -> None:
    job["state"] = "running"
    job["start"] = time.time()
    try:
        with open(job["logpath"], "w", encoding="utf-8", errors="replace") as logf:
            # shell=True so redirections (snmp-check > file) and quoting work.
            # text mode uses universal newlines, so carriage-return progress lines
            # from gobuster/ffuf arrive as discrete lines we can tail.
            proc = subprocess.Popen(
                job["command"], shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, errors="replace",
            )
            for line in proc.stdout:
                logf.write(line)
                stripped = line.strip()
                if stripped:
                    with lock:
                        job["last"] = stripped[:70]
            proc.wait()
            job["rc"] = proc.returncode
    except Exception as exc:
        job["rc"] = -1
        job["error"] = str(exc)
    job["end"] = time.time()

    rc = job.get("rc")
    if job.get("error"):
        job["state"] = "failed"
    elif rc == 0:
        job["state"] = "done"
    else:
        job["state"] = f"exit {rc}"

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
                    threads: int = 4) -> Optional[Dict[str, int]]:
    """Execute the live recon commands concurrently, with a live per-tool status table.

    Missing tools and missing wordlists are skipped before launch. Each tool's
    combined output is captured to a per-tool log under <loot>/_logs/.
    """
    live = runnable_suggestions(all_suggestions)
    if not live:
        warn("No runnable (unauthenticated) commands to execute.")
        return None

    _print_run_plan(live)

    loot_path = Path(loot)
    (loot_path / "ldap").mkdir(parents=True, exist_ok=True)
    logs_dir = loot_path / "_logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    # Build job records and pre-skip missing tools / wordlists before launch.
    jobs: List[Dict[str, Any]] = []
    for idx, s in enumerate(live):
        binary = s["command"].split()[0]
        job: Dict[str, Any] = {
            "tool": s["tool"], "host": s["host"], "command": s["command"],
            "state": "queued", "last": "", "rc": None, "start": None, "end": None,
            "error": "",
            "logpath": str(logs_dir / f"{safe_name(s['tool'])}_{safe_name(s['host'])}_{idx}.log"),
        }
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
    threads = max(1, threads)
    tty = sys.stdout.isatty()
    renderer = _LiveTable(enabled=tty)
    lock = threading.Lock()

    def build_lines() -> List[str]:
        now = time.time()
        running = sum(1 for j in jobs if j["state"] == "running")
        done = sum(1 for j in jobs if j["state"] == "done")
        skipped = sum(1 for j in jobs if j["state"].startswith("skip"))
        other = sum(1 for j in jobs if j["state"] == "failed" or j["state"].startswith("exit"))
        header = (f"Recon [{threads} workers]: {running} running, {done} done, "
                  f"{skipped} skipped, {other} other")
        lines = [color(header, C.BOLD)]
        for j in jobs:
            state = j["state"]
            disp = {"skip:no-tool": "skip (no tool)", "skip:no-wordlist": "skip (no wl)"}.get(state, state)
            elapsed = _fmt_elapsed((j["end"] or now) - j["start"]) if j["start"] else "--:--"
            row = f"  {j['tool']:<16}{j['host']:<16}{disp:<16}{elapsed}"
            if state == "running" and j["last"]:
                row += f"  | {j['last']}"
            lines.append(row)
        return lines

    print()
    if not tty:
        info(f"Running {len(to_run)} command(s) with up to {threads} workers; output -> {logs_dir}")
        for j in jobs:
            if j["state"].startswith("skip"):
                warn(f"[skip] {j['tool']} ({j['host']}): {j['state'].split(':', 1)[1]}")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for j in to_run:
            executor.submit(_run_worker, j, lock, tty)
        renderer.render(build_lines())
        while any(j["state"] in ("queued", "running") for j in to_run):
            renderer.render(build_lines())
            time.sleep(0.3)
        renderer.render(build_lines())

    ran = sum(1 for j in jobs if j["state"] == "done")
    skipped = sum(1 for j in jobs if j["state"].startswith("skip"))
    nonzero = sum(1 for j in jobs if j["state"].startswith("exit"))
    failed = sum(1 for j in jobs if j["state"] == "failed")

    print()
    good(f"Recon complete: {ran} ran clean, {skipped} skipped, {nonzero} non-zero exit, {failed} failed")
    good(f"Per-tool logs: {logs_dir}")
    return {"ran": ran, "skipped": skipped, "nonzero": nonzero, "failed": failed}


def run_pathfinder(pathfinder_path: str, loot: str) -> None:
    """Invoke PathFinder's scan mode on the loot directory."""
    pf = Path(pathfinder_path)
    if not (pf / "main" / "pathfinder.py").exists():
        err(f"PathFinder not found at '{pf}' (expected a sibling PathFinder/ with main/pathfinder.py).")
        return

    loot_abs = os.path.abspath(loot)
    info(f"Launching PathFinder on {loot_abs}")
    cmd = [sys.executable, "-m", "main.pathfinder", "scan", loot_abs]
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
        help="For LLM/API-like services, list discovered OpenAPI endpoints only",
    )
    parser.add_argument(
        "--llm-full",
        action="store_true",
        help="For LLM/API-like services, enumerate OpenAPI and probe config/model/chat paths",
    )
    parser.add_argument(
        "--hello",
        action="store_true",
        help="Send a test prompt to /chat when discovered during --llm-full enum",
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
        "--suggest",
        action="store_true",
        help="Print the follow-up enumeration commands for PathFinder to consume, "
             "and write a runnable recon script",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="Run the unauthenticated recon commands (skipping missing tools), then "
             "hand the results to PathFinder. Intended for the Kali/attack host.",
    )
    parser.add_argument(
        "--run-threads",
        type=int,
        default=4,
        help="Max enumeration tools to run concurrently with --run (default: 4)",
    )
    args = parser.parse_args()
    if args.run_threads < 1:
        parser.error("--run-threads must be >= 1.")
    if args.suggest and args.run:
        parser.error("Use either --suggest or --run, not both.")
    if args.llm_endpoint and args.llm_full:
        parser.error("Use either --llm-endpoint or --llm-full, not both.")
    if args.llm_endpoint and args.hello:
        parser.error("--hello requires --llm-full and cannot be used with --llm-endpoint.")
    if any(is_localhost_target(target) for target in args.targets):
        normalized = {target.strip().lower() for target in args.targets}
        if len(normalized) > 1:
            parser.error("When using localhost, run it by itself as the target.")
    return args


# =========================
# Main
# =========================

def main() -> None:
    args = parse_args()
    if args.no_color:
        set_color_mode(False)
    if args.hello:
        args.llm_full = True

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

    has_nmap = nmap_installed()
    use_local_fallback = not has_nmap and len(targets) == 1 and is_localhost_target(targets[0])

    if not has_nmap and not use_local_fallback:
        err("nmap not found in PATH. Install nmap, or run a localhost-only scan to use the built-in fallback.")
        sys.exit(1)
    if use_local_fallback:
        warn("nmap not found in PATH. Using localhost-only Python fallback mode.")

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
        info("LLM/API endpoint enum enabled for matching services")
    if args.llm_full:
        info("LLM/API full enum enabled for matching services")
    if args.hello:
        info("Hello prompt enabled for discovered /chat endpoints")
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

        if tcp_open_ports:
            try:
                tcp_result = (
                    localhost_tcp_service_scan(target, tcp_open_ports, host_dir)
                    if use_local_fallback
                    else tcp_service_scan(target, tcp_open_ports, host_dir)
                )
                ip_addr = tcp_result.get("ip", ip_addr)
                hostname = tcp_result.get("hostname", hostname)
                extra = merge_extra_info(extra, tcp_result.get("extra", {}))
                tcp_services = tcp_result.get("services", [])
                if args.llm_endpoint or args.llm_full:
                    try:
                        run_llm_enumeration(
                            target,
                            tcp_services,
                            send_hello=args.hello,
                            endpoint_only=args.llm_endpoint,
                            probe_all_http=use_local_fallback,
                        )
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

        if args.suggest or args.run:
            host_suggestions = suggest_for_host(
                ip_addr, tcp_services, udp_services,
                LOOT_DIR, DEFAULT_WEB_WORDLIST, DEFAULT_USER_WORDLIST,
            )
            if args.suggest:
                print_suggestions(ip_addr, host_suggestions)
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

    if args.suggest and all_suggestions:
        script_dir = base_outdir if (args.save and base_outdir) else Path(".")
        try:
            written = write_recon_scripts(script_dir, all_suggestions, LOOT_DIR)
            for path in written:
                good(f"Recon script written: {path}")
            good(f"Next: run the script, then `{PATHFINDER_SCAN_CMD} {LOOT_DIR}/`")
        except OSError as exc:
            err(f"Could not write recon script: {exc}")

    if args.run:
        if not all_suggestions:
            warn("--run: no suggestions generated from discovered services; nothing to run.")
        else:
            run_suggestions(
                all_suggestions, LOOT_DIR, DEFAULT_WEB_WORDLIST, DEFAULT_USER_WORDLIST,
                threads=args.run_threads,
            )
            pathfinder_path = str(Path(__file__).resolve().parent.parent / "PathFinder")
            run_pathfinder(pathfinder_path, LOOT_DIR)


if __name__ == "__main__":
    main()
