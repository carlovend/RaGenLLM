# scanner/nmap_runner.py

from typing import List, Dict, Any, Optional

import nmap

from .http_probe import probe_http_service, is_http_like


def _choose_best_cpe(cpe_field: Any) -> Optional[str]:
    """
    Nmap sometimes returns a list of CPE strings. Choose the most specific.
    """
    if not cpe_field:
        return None
    if isinstance(cpe_field, str):
        return cpe_field
    if isinstance(cpe_field, list):
        # heuristic: longest string is usually the most specific
        return max(cpe_field, key=len)
    return str(cpe_field)


def _apply_service_override(product: str, server_header: str) -> str:
    """
    Normalize product names using simple overrides (e.g., openresty -> nginx).
    """
    SERVICE_OVERRIDE = {
        "openresty": "nginx",
        "openresty nginx": "nginx",
        "httpd": "apache httpd",
    }
    base = (product or "").lower()
    hdr = (server_header or "").lower()
    # try exact override on product
    for k, v in SERVICE_OVERRIDE.items():
        if k in base or k in hdr:
            return v
    return product


def _normalize_service(raw_service: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a raw Nmap service dictionary with fingerprint, confidence score,
    and HTTP probe information.
    """
    product = raw_service.get("product") or ""
    version = raw_service.get("version") or ""
    extrainfo = raw_service.get("extrainfo") or ""
    cpe_raw = _choose_best_cpe(raw_service.get("cpe"))
    ip = raw_service.get("ip")
    port = raw_service.get("port")

    parts = []
    if product:
        parts.append(product.strip())
    if version:
        parts.append(version.strip())
    if extrainfo:
        parts.append(str(extrainfo).strip())
    if cpe_raw:
        parts.append(str(cpe_raw).strip())
    fingerprint = " | ".join([p for p in parts if p]) or None

    http_probe = {}
    # HTTP probe is allowed to fail silently, but we try once
    try:
        http_probe = probe_http_service(ip, port, use_ssl_guess=(port == 443))
    except Exception:
        http_probe = {}

    server_header = (http_probe.get("server_header") or "").strip() if http_probe else ""
    favicon = http_probe.get("favicon_sha1") if http_probe else None

    normalized = _apply_service_override(product or "", server_header or "")

    score = 0
    if normalized:
        score += 2
    if cpe_raw:
        score += 3
    if version:
        score += 1
    if server_header:
        score += 2
    if favicon:
        score += 2
    confidence = min(10, score)

    raw_service["fingerprint"] = fingerprint
    raw_service["normalized_product"] = normalized
    raw_service["confidence"] = confidence
    raw_service["http_probe"] = http_probe or {}
    raw_service["favicon_sha1"] = favicon or None
    return raw_service


def run_nmap_scan(target: str, ports: str = "1-10000", arguments: str = "-sV") -> List[Dict[str, Any]]:
    """
    Run Nmap on a target and return a list of normalized services.

    Each service dict has at least:
        - ip
        - port
        - name
        - product
        - version
        - protocol
        - fingerprint
        - normalized_product
        - confidence
        - http_probe
        - favicon_sha1
    """
    scanner = nmap.PortScanner()
    scanner.scan(target, ports, arguments=arguments)

    services: List[Dict[str, Any]] = []

    for host in scanner.all_hosts():
        ip = host
        for proto in scanner[host].all_protocols():
            ports_list = scanner[host][proto].keys()
            for p in ports_list:
                s = scanner[host][proto][p]
                service = {
                    "ip": ip,
                    "port": int(p),
                    "protocol": proto,
                    "name": s.get("name"),
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "extrainfo": s.get("extrainfo"),
                    "cpe": s.get("cpe"),
                    "state": s.get("state"),
                }
                normalized = _normalize_service(service)
                services.append(normalized)

    return services
