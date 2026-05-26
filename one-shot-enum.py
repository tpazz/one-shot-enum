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
    - With --llm, detect LLM/API-like services, list OpenAPI paths, and probe useful config endpoints
    - With --hello, send a test prompt to /chat when discovered
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
import queue
import re
import shutil
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


def check_nmap_installed() -> None:
    if shutil.which("nmap") is None:
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


def enumerate_llm_service(target: str, service: Service, send_hello: bool = False) -> Dict[str, Any]:
    base_url = service_base_url(target, service)
    openapi_url = f"{base_url}{OPENAPI_CANDIDATE_PATHS[0]}"
    openapi_response = http_request(openapi_url)

    result: Dict[str, Any] = {
        "base_url": base_url,
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


def run_llm_enumeration(target: str, tcp_services: List[Service], send_hello: bool = False) -> None:
    for service in tcp_services:
        if not resembles_llm_service(service):
            continue

        port = service.get("port", "")
        info(f"{target}:{port}: LLM/API-like service found; probing endpoints")
        service["llm_enum"] = enumerate_llm_service(target, service, send_hello=send_hello)


def llm_enum_lines(llm_enum: Dict[str, Any]) -> List[str]:
    lines: List[str] = ["LLM/API enum:"]
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
        "--llm",
        action="store_true",
        help="For LLM/API-like services, enumerate OpenAPI and probe config paths",
    )
    parser.add_argument(
        "--hello",
        action="store_true",
        help="Send a test prompt to /chat when discovered during LLM/API enum",
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
        "--outdir",
        default="scan_results",
        help="Base output directory when --save is used (default: scan_results)",
    )
    args = parser.parse_args()
    if any(is_localhost_target(target) for target in args.targets):
        normalized = {target.strip().lower() for target in args.targets}
        if len(normalized) > 1:
            parser.error("When using localhost, run it by itself as the target.")
    return args


# =========================
# Main
# =========================

def main() -> None:
    check_nmap_installed()
    args = parse_args()
    if args.hello:
        args.llm = True

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
        info(f"UDP enabled: top {args.udp_top_ports} ports (timing: T3)")
    if args.llm:
        info("LLM/API enum enabled for matching services")
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
                tcp_result = tcp_service_scan(target, tcp_open_ports, host_dir)
                ip_addr = tcp_result.get("ip", ip_addr)
                hostname = tcp_result.get("hostname", hostname)
                extra = merge_extra_info(extra, tcp_result.get("extra", {}))
                tcp_services = tcp_result.get("services", [])
                if args.llm:
                    try:
                        run_llm_enumeration(target, tcp_services, send_hello=args.hello)
                    except Exception as exc:
                        err(f"{target}: LLM/API enum failed: {exc}")
            except Exception as exc:
                err(f"{target}: TCP service scan failed: {exc}")
        else:
            warn(f"{target}: skipping TCP service scan because no TCP ports were discovered")

        if args.udp:
            try:
                info(f"{target}: running UDP top-ports scan")
                udp_result = udp_scan(target, args.udp_top_ports, host_dir)
                udp_services = udp_result.get("udp_services", [])
            except Exception as exc:
                err(f"{target}: UDP scan failed: {exc}")

        print_host_summary(ip_addr, hostname, extra, tcp_services, udp_services)

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


if __name__ == "__main__":
    main()
