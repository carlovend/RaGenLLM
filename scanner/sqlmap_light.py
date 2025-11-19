# scanner/sqlmap_light.py

import os
import sys
import re
import time
import shlex
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

SQLMAP_TIMEOUT_LIGHT = int(os.environ.get("SQLMAP_TIMEOUT_LIGHT", "180"))
SQLMAP_RESULTS_DIR = os.path.join("results", "sqlmap_light")
os.makedirs(SQLMAP_RESULTS_DIR, exist_ok=True)

_env_bin = os.environ.get("SQLMAP_BIN")
_detected_bin = shutil.which("sqlmap")
_local_sqlmap_py = os.path.expanduser("~/sqlmap/sqlmap.py")
SQLMAP_BIN: Optional[str] = None


def _is_executable_file(path: str) -> bool:
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


# resolve SQLMAP_BIN once at import time
if _env_bin:
    env_base = os.path.basename(_env_bin).lower()
    if "sqlite" in env_base and "sqlmap" not in env_base:
        print(f"[sqlmap-light] WARNING: SQLMAP_BIN='{_env_bin}' looks like sqlite, ignoring.")
    else:
        resolved = shutil.which(_env_bin) or _env_bin
        if _is_executable_file(resolved) or resolved.endswith(".py"):
            SQLMAP_BIN = resolved

if not SQLMAP_BIN and _detected_bin:
    SQLMAP_BIN = _detected_bin

if not SQLMAP_BIN and os.path.exists(_local_sqlmap_py):
    SQLMAP_BIN = _local_sqlmap_py

if not SQLMAP_BIN:
    print("[sqlmap-light] INFO: sqlmap not auto-resolved. You can install it or clone https://github.com/sqlmapproject/sqlmap.git ~/sqlmap")
else:
    print(f"[sqlmap-light] INFO: sqlmap resolved to: {SQLMAP_BIN}")


def _build_sqlmap_command(url: str, extra_args: List[str]) -> List[str]:
    """
    Build the sqlmap command for a given URL and extra args.
    Tries (in order): env SQLMAP_BIN, system sqlmap, local ~/sqlmap/sqlmap.py,
    docker image `sqlmapproject/sqlmap`.
    """
    base_args = list(extra_args)

    # ensure output-dir
    if SQLMAP_RESULTS_DIR and "--output-dir" not in base_args:
        base_args += ["--output-dir", SQLMAP_RESULTS_DIR]

    # prefer SQLMAP_BIN if valid
    if SQLMAP_BIN:
        lb = os.path.basename(SQLMAP_BIN).lower()
        if "sqlite" in lb and "sqlmap" not in lb:
            raise FileNotFoundError(f"SQLMAP_BIN seems to point to sqlite ('{SQLMAP_BIN}').")
        if SQLMAP_BIN.endswith(".py"):
            return ["python3", SQLMAP_BIN, "-u", url] + base_args
        if _is_executable_file(SQLMAP_BIN):
            return [SQLMAP_BIN, "-u", url] + base_args

    # binary in PATH
    if shutil.which("sqlmap"):
        return ["sqlmap", "-u", url] + base_args

    # local repo
    local = os.path.expanduser("~/sqlmap/sqlmap.py")
    if os.path.exists(local):
        return ["python3", local, "-u", url] + base_args

    # docker fallback
    if shutil.which("docker"):
        if sys.platform == "darwin":
            return [
                "docker", "run", "--rm",
                "--add-host", "host.docker.internal:host-gateway",
                "sqlmapproject/sqlmap", "-u", url
            ] + base_args
        else:
            return [
                "docker", "run", "--rm",
                "--network", "host",
                "sqlmapproject/sqlmap", "-u", url
            ] + base_args

    raise FileNotFoundError("sqlmap not found: install it or clone the repo in ~/sqlmap")


def run_sqlmap_light_on_url(url: str, timeout: int = SQLMAP_TIMEOUT_LIGHT) -> Dict[str, Any]:
    """
    Execute sqlmap in a "light" configuration against a single URL.

    Returns:
        dict: {
            "url": str,
            "found": bool,
            "log": str (path to logfile),
            "rc": int,
            "time": float,
            "details": dict
        }
    """
    # basic extra args; you can tune these or drive from env
    extra = [
        "--batch", "--level=3", "--risk=3", "--threads=4",
        "--random-agent", "--flush-session", "--ignore-code=401",
        "--forms", "--crawl=2"
    ]

    cmd = _build_sqlmap_command(url, extra)
    log_ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_url = re.sub(r"[^a-zA-Z0-9_.-]", "_", url)
    logfile = os.path.join(SQLMAP_RESULTS_DIR, f"sqlmap_{log_ts}_{safe_url}.log")
    cmd_display = " ".join(shlex.quote(c) for c in cmd)

    start = time.time()
    details: Dict[str, Any] = {"command": cmd_display}

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        took = time.time() - start
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")

        with open(logfile, "w", encoding="utf-8") as fh:
            fh.write(f"COMMAND: {cmd_display}\n\n")
            fh.write(out)

        details["rc"] = proc.returncode

        patterns = [
            r"(?i)is vulnerable",
            r"(?i)parameter .* is vulnerable",
            r"(?i)parameter .* seems to be injectable",
            r"(?i)sql injection",
            r"(?i)web application is vulnerable",
            r"(?i)payload",
            r"(?i)back-end DBMS",
            r"(?i)heuristic.*positive",
        ]
        found = any(re.search(pat, out) for pat in patterns)

        return {
            "url": url,
            "found": bool(found),
            "log": logfile,
            "rc": proc.returncode,
            "time": round(took, 2),
            "details": details,
        }

    except subprocess.TimeoutExpired:
        print(f"[sqlmap-light] Timeout after {timeout}s for {url}")
        with open(logfile, "w", encoding="utf-8") as fh:
            fh.write(f"COMMAND: {cmd_display}\n\nTIMEOUT after {timeout}s\n")
        return {
            "url": url,
            "found": False,
            "log": logfile,
            "rc": -1,
            "time": timeout,
            "details": {"timeout": timeout, "command": cmd_display},
        }
    except Exception as e:
        print(f"[sqlmap-light] Error running sqlmap on {url}: {e}")
        with open(logfile, "w", encoding="utf-8") as fh:
            fh.write("ERROR\n")
            fh.write(f"COMMAND: {cmd_display}\n\n")
            fh.write(str(e))
        return {
            "url": url,
            "found": False,
            "log": logfile,
            "rc": -2,
            "time": 0.0,
            "details": {"error": str(e), "command": cmd_display},
        }
