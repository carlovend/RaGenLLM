
from typing import List, Dict, Any
from src.scanning.utils import apply_service_override

def print_summary(services: List[Dict[str, Any]]):
    """
    Prints a detailed summary of found services and vulnerabilities,
    resembling the original output format.
    """
    print("\n" + "=" * 50)
    print("SCAN RESULTS SUMMARY")
    print("=" * 50)

    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

    for i, service in enumerate(services):
        print("-" * 50)
        # Handle manual override logic if present in model (defaulting to product)
        shown_product = service.get("user_confirmed_product") or service.get("normalized_product") or service.get("product") or "N/A"
        version = service.get("version") or ""
        print(f"Service {i+1}: {shown_product} {version}")
        print(f"  Target: {service.get('ip')}:{service.get('port')}")
        
        # Show Fingerprint if available
        if service.get("fingerprint"):
            print(f"  Fingerprint: {service['fingerprint']}")

        # Map CVE -> severity from Nuclei findings
        cve_severities = {}
        for finding in service.get("nuclei_findings", []):
            info = finding.get("info", {}) or {}
            sev = (info.get("severity") or "unknown").lower()
            
            # Extract CVEs again locally just to map severity (or use cached extraction if improved model)
            # For display purposes, we iterate strictly to find severities
            cls = info.get("classification", {}) or {}
            cves_in_finding = []
            if cls.get("cve-id"):
                val = cls.get("cve-id")
                cves_in_finding.extend([val] if isinstance(val, str) else val)
            
            for c in cves_in_finding:
                cve_severities[c.upper()] = sev

        # Consolidated CVE List
        service_cves = sorted(set(service.get("cves", [])))
        
        if service_cves:
            # Sort by severity
            def sev_key(cve):
                return SEV_ORDER.get(cve_severities.get(cve.upper(), "unknown"), 5), cve
            
            ordered = sorted(service_cves, key=sev_key)

            print("  Vulnerabilities (CVEs):")
            for cve in ordered:
                sev = cve_severities.get(cve.upper(), "unknown").upper()
                print(f"    - {cve} (Severity: {sev})")
        else:
            print("  No CVEs detected.")

        # Other Nuclei findings (NO CVE)
        other_findings = []
        for finding in service.get("nuclei_findings", []):
             # Simple check: if we didn't extract CVEs from it, show it as generic finding
             # (This is a simplified re-implementation of original logic)
             info = finding.get("info",{})
             if not info.get("classification", {}).get("cve-id"):
                 other_findings.append(finding)

        if other_findings:
            print("  Other Nuclei Findings:")
            for finding in other_findings:
                template_id = finding.get("template-id", "N/A")
                name = finding.get("info", {}).get("name", "N/A")
                severity = (finding.get("info", {}).get("severity") or "unknown").upper()
                print(f"    - [{severity}] {name} ({template_id})")

    print("-" * 50)
