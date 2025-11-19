# scanner/nuclei_runner.py

import json
import subprocess
from typing import List, Dict, Any, Optional


def run_nuclei_scan(
    target_url: str,
    templates: Optional[str] = None,
    timeout: int = 60,
) -> List[Dict[str, Any]]:
    """
    Run Nuclei against a single URL and return parsed JSON findings (list of dicts).
    """
    cmd = ["nuclei", "-u", target_url, "-json"]
    if templates:
        cmd += ["-t", templates]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[Nuclei] Timeout on {target_url}")
        return []
    except FileNotFoundError:
        print("[Nuclei] nuclei binary not found in PATH.")
        return []

    findings: List[Dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            findings.append(data)
        except json.JSONDecodeError:
            continue

    return findings


def extract_cves_from_nuclei_finding(finding: Dict[str, Any]) -> List[str]:
    """
    Try to extract CVE identifiers from a Nuclei finding.
    """
    cves: List[str] = []

    # standard nuclei format: info.cve or info.tags
    info = finding.get("info") or {}
    if isinstance(info, dict):
        if info.get("cve"):
            val = info["cve"]
            if isinstance(val, str):
                cves.append(val)
            elif isinstance(val, list):
                cves.extend(val)

        tags = info.get("tags")
        if tags:
            if isinstance(tags, str):
                tags_list = tags.split(",")
            else:
                tags_list = list(tags)
            for t in tags_list:
                t = t.strip()
                if t.upper().startswith("CVE-"):
                    cves.append(t)

    # de-duplicate and normalize
    cleaned = []
    for c in cves:
        c = c.upper().strip()
        if c not in cleaned:
            cleaned.append(c)
    return cleaned
