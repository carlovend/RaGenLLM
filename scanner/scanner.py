# scanner/scanner.py

import re
from multiprocessing import Pool, cpu_count
from typing import List, Dict, Any, Tuple

from .nmap_runner import run_nmap_scan
from .http_probe import is_http_like, get_url
from .nuclei_runner import run_nuclei_scan, extract_cves_from_nuclei_finding
from .sqlmap_light import run_sqlmap_light_on_url


class Scanner:
    """
    High-level scanner orchestrator for the RaGenLLM pipeline.

    Responsibilities:
      - run Nmap and normalize services
      - optionally run Nuclei on HTTP-like services (parallel)
      - optionally run sqlmap-light on candidate URLs (parallel)
      - return:
            services: List[dict]
            sqli_bundle: {"urls": [...], "results": [...]}
    """

    def __init__(
        self,
        enable_nuclei: bool = True,
        enable_sqlmap: bool = False,
        fast: bool = False,
        max_workers: int | None = None,
    ):
        self.enable_nuclei = enable_nuclei
        self.enable_sqlmap = enable_sqlmap
        self.fast = fast
        self.max_workers = max_workers or max(2, cpu_count() // 2)

    # ---------------- Public API ----------------

    def run(self, ip: str, ports: str = "1-10000") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Main entry point: runs the full scanning pipeline.

        Returns:
            services: list of enriched service dictionaries
            sqli_bundle: {"urls": [...], "results": [...]}
        """
        print(f"[Scanner] Starting scans on {ip}:{ports}")
        services = run_nmap_scan(ip, ports)

        if not services:
            print("[Scanner] No services found by Nmap.")
            return [], {"urls": [], "results": []}

        print(f"[Scanner] Nmap found {len(services)} services.")

        # If fast mode, stop here (no nuclei, no sqlmap)
        if self.fast:
            print("[Scanner] Fast mode active: skipping Nuclei and sqlmap-light.")
            return services, {"urls": [], "results": []}

        # Nuclei per each HTTP-like service, in parallel
        if self.enable_nuclei:
            services, sqlmap_candidate_urls = self._run_nuclei_phase(services)
        else:
            sqlmap_candidate_urls = []

        # sqlmap-light phase
        sqli_bundle = {"urls": sqlmap_candidate_urls, "results": []}
        if self.enable_sqlmap and sqlmap_candidate_urls:
            print(f"[Scanner] Running sqlmap-light on {len(sqlmap_candidate_urls)} URLs.")
            sqli_results = self._run_sqlmap_phase(sqlmap_candidate_urls)
            sqli_bundle["results"] = sqli_results
        else:
            if self.enable_sqlmap:
                print("[Scanner] No candidate URLs for sqlmap-light.")

        return services, sqli_bundle

    # ---------------- Internal phases ----------------

    def _run_nuclei_phase(
        self, services: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Runs Nuclei in parallel on HTTP-like services.
        Also extracts CVEs and candidate URLs for sqlmap-light.
        """
        http_services = [
            s for s in services
            if is_http_like(s) or (s.get("http_probe") or {}).get("reachable")
        ]
        if not http_services:
            print("[Scanner] No HTTP-like services for Nuclei.")
            return services, []

        base_urls = [get_url(s) for s in http_services]
        print(f"[Scanner] Running Nuclei on {len(base_urls)} HTTP-like services using {self.max_workers} workers.")

        with Pool(self.max_workers) as pool:
            nuclei_results_list = pool.map(run_nuclei_scan, base_urls)

        sqlmap_candidate_urls: List[str] = []

        # attach results back to services, extract CVEs and host URLs
        for service, nuclei_results in zip(http_services, nuclei_results_list):
            service["nuclei_findings"] = nuclei_results or []
            service.setdefault("cves", [])

            if not nuclei_results:
                continue

            for finding in nuclei_results:
                try:
                    found_cves = extract_cves_from_nuclei_finding(finding) or []
                except Exception as e:
                    print(f"[Scanner][Nuclei] Warning: error parsing finding: {e}")
                    found_cves = []

                for cve_id in found_cves:
                    if isinstance(cve_id, str) and re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id, flags=re.IGNORECASE):
                        cve_clean = cve_id.upper().strip()
                        if cve_clean not in service["cves"]:
                            service["cves"].append(cve_clean)

                host = (
                    finding.get("host")
                    or finding.get("matched-at")
                    or finding.get("matches")
                    or None
                )
                if isinstance(host, str) and host.startswith(("http://", "https://")):
                    sqlmap_candidate_urls.append(host)
                else:
                    base_url = get_url(service)
                    sqlmap_candidate_urls.append(base_url)

        # dedupe URLs
        sqlmap_candidate_urls = list(dict.fromkeys(sqlmap_candidate_urls))
        print(f"[Scanner] Collected {len(sqlmap_candidate_urls)} candidate URLs for sqlmap-light.")
        return services, sqlmap_candidate_urls

    def _run_sqlmap_phase(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Runs sqlmap-light in parallel on a list of URLs.
        """
        if not urls:
            return []
        with Pool(self.max_workers) as pool:
            results = pool.map(run_sqlmap_light_on_url, urls)
        return results
