# scanner/http_probe.py

import hashlib
from typing import Dict, Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

COMMON_HTTP_PORTS = {
    80, 81, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9080, 9090,
    9200, 9300, 9443, 15672, 5601, 5000, 3000, 7001
}

# semplice cache in-memory su base (ip, port)
_PROBE_CACHE: Dict[str, Dict[str, Any]] = {}


def is_http_like(service: dict) -> bool:
    """
    Heuristics to guess if a given Nmap service is HTTP-like.
    """
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


def get_url(service: dict) -> str:
    """
    Build a base URL from a service dict (ip, port, protocol).
    """
    port = service["port"]
    name = (service.get("name") or "").lower()
    https_ports = {443, 8443, 9443}
    scheme = "https" if ("ssl" in name or port in https_ports) else "http"
    return f"{scheme}://{service['ip']}:{port}"


def _sha1_of_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def probe_http_service(
    ip: str,
    port: int,
    use_ssl_guess: bool = False,
    timeout: float = 0.3,
) -> Dict[str, Any]:
    """
    Performs a lightweight HTTP probe (HEAD + favicon) with aggressive timeout.
    Results are cached in memory.
    """
    key = f"{ip}:{port}"
    if key in _PROBE_CACHE:
        return _PROBE_CACHE[key]

    result: Dict[str, Any] = {
        "server_header": None,
        "powered_by": None,
        "favicon_sha1": None,
        "reachable": False,
    }
    scheme = "https" if use_ssl_guess or port == 443 else "http"
    base = f"{scheme}://{ip}:{port}"

    try:
        r = requests.head(base, timeout=timeout, allow_redirects=True, verify=False)
        if 200 <= r.status_code < 600:
            result["reachable"] = True
        result["server_header"] = r.headers.get("Server") or r.headers.get("server")
        result["powered_by"] = r.headers.get("X-Powered-By") or r.headers.get("x-powered-by")

        # prova a scaricare favicon in modo best-effort
        try:
            fav = requests.get(base + "/favicon.ico", timeout=timeout, verify=False)
            if fav.status_code == 200 and fav.content:
                result["favicon_sha1"] = _sha1_of_bytes(fav.content)
        except Exception:
            pass
    except Exception:
        # host lento o non raggiungibile -> keep defaults
        pass

    _PROBE_CACHE[key] = result
    return result
