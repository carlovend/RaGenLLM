
import shutil
import os
import re
import hashlib
from typing import Optional, List, Dict
import requests
from urllib.parse import urljoin

from src.core.config import COMMON_HTTP_PORTS, SERVICE_OVERRIDE
from src.core.models import ServiceInfo

def is_http_like(service: Dict) -> bool:
    # Logic extracted from original nmap_scan.py
    name = (service.get("name") or "").lower()
    port = service.get("port")
    proto = (service.get("protocol") or "").lower()
    http_probe = service.get("http_probe") or {}
    reachable = bool(http_probe.get("reachable"))
    server_hdr = (http_probe.get("server_header") or "").lower()

    return (
        (port in COMMON_HTTP_PORTS)
        or ("http" in name)
        or ("ssl/http" in proto)
        or reachable
        or ("nginx" in server_hdr)
        or ("apache" in server_hdr)
        or ("jetty" in server_hdr)
        or ("openresty" in server_hdr)
    )

def probe_http_service(ip: str, port: int, use_ssl_guess: bool = False, timeout: int = 5) -> Dict:
    result = {"server_header": None, "powered_by": None, "favicon_sha1": None, "title": None, "reachable": False}
    scheme = "https" if use_ssl_guess or port == 443 else "http"
    base = f"{scheme}://{ip}:{port}"

    try:
        r = requests.get(base, timeout=timeout, allow_redirects=True, verify=False)
        if r.status_code:
            result["reachable"] = True
        result["server_header"] = r.headers.get("Server") or r.headers.get("server")
        result["powered_by"] = r.headers.get("X-Powered-By") or r.headers.get("x-powered-by")
        
        # Extract Title
        match = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
        if match:
            result["title"] = match.group(1).strip()
            
    except Exception:
        return result

    try:
        fav_url = urljoin(base, "/favicon.ico")
        f = requests.get(fav_url, timeout=timeout, allow_redirects=True, verify=False)
        if f.status_code == 200 and f.content:
            sha1 = hashlib.sha1(f.content).hexdigest()
            result["favicon_sha1"] = sha1
    except Exception:
        pass

    return result

def apply_service_override(product: str, server_header: str = None, title: str = None) -> str:
    base = (product or "").lower()
    
    # Check title for common products
    if title:
        t = title.lower()
        if "metabase" in t: return "Metabase"
        if "jenkins" in t: return "Jenkins"
        if "grafana" in t: return "Grafana"
        if "gitlab" in t: return "GitLab"
    
    server = (server_header or "").lower()
    for k, v in SERVICE_OVERRIDE.items():
        if k in base or k in server:
            return v
            
    if server:
        if "openresty" in server: return "nginx"
        if "cloudflare" in server: return "cloudflare"
        if "jetty" in server and not product: return "Jetty"
        
    return product or server_header or title

def normalize_service(raw_service: Dict) -> Dict:
    # Logic extracted from _normalize_service in nmap_scan.py
    product = raw_service.get("product") or ""
    version = raw_service.get("version") or ""
    extrainfo = raw_service.get("extrainfo") or ""
    cpe_raw = raw_service.get("cpe")
    
    # flatten cpe if needed (logic simplified)
    if isinstance(cpe_raw, list) and cpe_raw:
        cpe_raw = cpe_raw[0] # simplification
    
    ip = raw_service.get("ip")
    port = raw_service.get("port")

    parts = []
    if product: parts.append(product.strip())
    if version: parts.append(version.strip())
    if extrainfo: parts.append(str(extrainfo).strip())
    if cpe_raw: parts.append(str(cpe_raw).strip())
    fingerprint = " | ".join([p for p in parts if p]) or None

    http_probe = {}
    if is_http_like(raw_service):
        try:
            http_probe = probe_http_service(ip, port, use_ssl_guess=(port == 443))
        except Exception:
            http_probe = {}
    
    server_header = (http_probe.get("server_header") or "").strip() if http_probe else ""
    title = (http_probe.get("title") or "").strip() if http_probe else ""
    favicon = http_probe.get("favicon_sha1") if http_probe else None
    
    # Use title if product is weak (tcpwrapped/unknown)
    if (not product or product.lower() in ["tcpwrapped", "unknown", "jetty", "winstone"]) and title:
        normalized = apply_service_override(product, server_header, title)
    else:
        normalized = apply_service_override(product or "", server_header, title)
    
    # If we changed the product name (e.g. Jetty -> Metabase), the version (e.g. 9.4.4) 
    # likely belongs to the old product (Jetty), not the new one. Clear it to avoid confusion.
    if normalized and product and normalized.lower() != product.lower():
        # Only clear if the product was substantial (not just empty)
        # and we switched to something retrieved from title/header override
        if product.lower() not in normalized.lower(): 
            version = "" # Clear misleading version
    
    # Calculate confidence (simplified logic)
    score = 0
    if normalized: score += 2
    if cpe_raw: score += 3
    if version: score += 1
    if server_header: score += 2
    if favicon: score += 2
    confidence = min(10, score)

    raw_service.update({
        "fingerprint": fingerprint,
        "normalized_product": normalized,
        "confidence": confidence,
        "http_probe": http_probe,
        "favicon_sha1": favicon,
        "version": version  # Update version in case it was cleared
    })
    return raw_service

def extract_cves_from_nuclei_finding(finding: Dict) -> List[str]:
    cves = set()
    info = finding.get("info", {}) or {}

    cls = info.get("classification", {}) or {}
    cve_field = cls.get("cve-id")
    if isinstance(cve_field, str):
        cves.add(cve_field.upper().strip())
    elif isinstance(cve_field, list):
        cves.update(c.upper().strip() for c in cve_field if isinstance(c, str))

    cve_alt = info.get("cve")
    if isinstance(cve_alt, str):
        cves.add(cve_alt.upper().strip())
    elif isinstance(cve_alt, list):
        cves.update(c.upper().strip() for c in cve_alt if isinstance(c, str))

    meta = finding.get("metadata", {}) or {}
    md_cve = meta.get("cve")
    if isinstance(md_cve, str):
        cves.add(md_cve.upper().strip())
    return sorted([c for c in cves if re.search(r"CVE-\d{4}-\d{4,7}", c, flags=re.IGNORECASE)])
