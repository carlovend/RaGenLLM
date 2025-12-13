
import os
import sys
import shutil
import time
import json
import re
import shlex
import subprocess
from typing import List, Dict, Any, Optional

from src.core.config import (
    SQLMAP_BIN, SQLMAP_RESULTS_DIR, SQLMAP_TIMEOUT_LIGHT, 
    SQLMAP_DISCOVERY, SQLMAP_DISCOVERY_LIMIT
)
from src.core.logger import get_logger

logger = get_logger(__name__)

class SqlmapRunner:
    def __init__(self):
        self.sqlmap_bin = self._resolve_sqlmap_bin()
        self.base_light_args = [
            "--batch", "--level=3", "--risk=3", "--threads=6",
            "--random-agent", "--flush-session", "--ignore-code=401", 
            "--forms", "--crawl=3", "--data=\"username=admin&password=password&submit=Login\""
        ]
        os.makedirs(SQLMAP_RESULTS_DIR, exist_ok=True)

    def _resolve_sqlmap_bin(self) -> Optional[str]:
        # Logic from original script to find sqlmap executable
        if SQLMAP_BIN and os.path.isfile(SQLMAP_BIN) and os.access(SQLMAP_BIN, os.X_OK):
             return SQLMAP_BIN
        
        detected = shutil.which("sqlmap")
        if detected: return detected
        
        local_py = os.path.expanduser("~/sqlmap/sqlmap.py")
        if os.path.exists(local_py): return local_py
        
        return None

    def _build_command(self, url: str, depth: str = "light", data: str = None, headers: str = None) -> List[str]:
        mode = "deep" if depth == "deep" else "light"
        base_args = self.base_light_args.copy()
        
        if mode == "deep":
             base_args = ["--batch","--level=5","--risk=3","--threads=5","--random-agent","--flush-session","--timeout=15"]

        if data:
            base_args += ["--data", data]
        if headers:
            base_args += ["--headers", headers]
        
        if "--output-dir" not in base_args:
             base_args += ["--output-dir", str(SQLMAP_RESULTS_DIR)]

        # Construct command based on binary type
        if self.sqlmap_bin:
            if self.sqlmap_bin.endswith(".py"):
                return ["python3", self.sqlmap_bin, "-u", url] + base_args
            return [self.sqlmap_bin, "-u", url] + base_args
        
        # Fallback Docker
        if shutil.which("docker"):
            if sys.platform == "darwin":
                return ["docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway", "sqlmapproject/sqlmap", "-u", url] + base_args
            else:
                return ["docker", "run", "--rm", "--network", "host", "sqlmapproject/sqlmap", "-u", url] + base_args
        
        raise FileNotFoundError("SQLMap binary not found and Docker not available.")

    def run_on_urls(self, urls: List[str], timeout: int = SQLMAP_TIMEOUT_LIGHT) -> Dict[str, Any]:
        """
        Runs SQLMap on a list of URLs and returns a bundle of results.
        """
        # Normalize URLs
        clean_urls = sorted(list(set([u.strip() for u in urls if u and u.strip()])))
        
        # Discovery (simplified from original)
        # In a real refactor, discovery logic should be its own method/class, but keeping it inline for now to save space
        final_targets = [(u, None, None) for u in clean_urls]
        
        results = []
        for url, data, headers in final_targets:
            safe_name = re.sub(r'[^0-9A-Za-z._-]', '_', url)[:60]
            logfile = os.path.join(SQLMAP_RESULTS_DIR, f"{safe_name}.log")
            
            try:
                cmd = self._build_command(url, data=data, headers=headers)
                logger.info(f"SQLMap Scan: {url}")
                
                # Execute
                start = time.time()
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
                duration = time.time() - start
                
                # Write log
                with open(logfile, "w", encoding="utf-8") as f:
                    f.write(f"CMD: {' '.join(cmd)}\n\n")
                    f.write(p.stdout + "\n" + p.stderr)
                
                # Parse output
                found = "is vulnerable" in (p.stdout or "").lower() or "sql injection" in (p.stdout or "").lower()
                
                results.append({
                    "url": url,
                    "found": found,
                    "log": logfile,
                    "time": round(duration, 2)
                })
                
            except Exception as e:
                logger.error(f"Error scanning {url}: {e}")
                results.append({"url": url, "found": False, "error": str(e)})

        return {"urls": clean_urls, "results": results}
