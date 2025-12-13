
#!/usr/bin/env python3
import sys
import os

# Ensure src is in python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.core.logger import get_logger
from src.core.printer import print_summary
from src.scanning.nmap_runner import NmapRunner
from src.scanning.nuclei_runner import NucleiRunner
from src.scanning.utils import extract_cves_from_nuclei_finding
from src.orchestration.feedback_manager import FeedbackManager

logger = get_logger("Main")

def main():
    print("🚀 Tesi API Refactored - PoC Generator")
    print("=" * 50)

    # 1. Input
    try:
        ip = input("Target IP: ").strip()
        ports = input("Target Port(s): ").strip()
        if not ip or not ports:
            logger.error("IP and Port are required.")
            return
    except KeyboardInterrupt:
        return

    # 2. Scanning Phase
    logger.info("Starting Nmap Scan...")
    nmap_runner = NmapRunner()
    services = nmap_runner.scan(ip, ports)
    
    if not services:
        logger.warning("No services found.")
        return

    # 3. Nuclei Phase
    logger.info("Running Nuclei on http services...")
    nuclei_runner = NucleiRunner()
    
    for svc in services:
        # Check if HTTP-like or just try blindly if it has an http probe or common port
        if svc.get("http_probe", {}).get("reachable") or svc.get("port") in {80, 443, 8080}:
            url = f"http://{svc['ip']}:{svc['port']}" # Simplified
            
            # Better scheme detection logic
            if svc.get("port") in {443, 8443} or "ssl" in svc.get("name", ""):
                 url = f"https://{svc['ip']}:{svc['port']}"

            logger.info(f"Scanning {url} with Nuclei...")
            findings = nuclei_runner.scan(url)
            svc['nuclei_findings'] = findings
            
            # Extract CVEs from Nuclei and merge with Nmap's
            for f in findings:
                cves = extract_cves_from_nuclei_finding(f)
                if cves:
                    current_cves = set(svc.get('cves', []))
                    current_cves.update(cves)
                    svc['cves'] = list(current_cves)

    # 4. Print Detailed Summary (Restored Feature)
    print_summary(services)

    # 5. Selection Loop
    while True:
        try:
            choice = input("\nSelect service index to exploit (or 'q' to quit): ").strip()
            if choice.lower() == 'q':
                break
            
            if not choice.isdigit() or not (1 <= int(choice) <= len(services)):
                print("Invalid selection.")
                continue

            selected_svc = services[int(choice) - 1]
            cves = selected_svc.get("cves", [])

            # Allow manual CVE entry regardless of findings
            print(f"Detected CVEs: {', '.join(cves) if cves else 'None'}")
            manual_cve = input("Enter a specific CVE to test (or enter to use detected only): ").strip()
            if manual_cve:
                manual_cve = manual_cve.upper()
                if cves:
                    # If we already have CVEs, ask if we want to isolate the manual one
                    overwrite = input(f"Run ONLY {manual_cve}? (Y/n - 'n' adds it to the list): ").strip().lower()
                    if overwrite in ["", "y", "yes"]:
                        cves = [manual_cve]
                    else:
                        # Add to list but prioritize it at the beginning
                        if manual_cve in cves:
                            cves.remove(manual_cve)
                        cves.insert(0, manual_cve)
                else:
                    cves = [manual_cve]

            if not cves:
                logger.warning("No CVEs to test.")
                continue

            # 6. Feedback Loop
            fb_manager = FeedbackManager()
            for cve in cves:
                print(f"\n--- Testing {cve} ---")
                fb_manager.run_feedback_loop(selected_svc, cve)

        except KeyboardInterrupt:
            break

    print("Goodbye.")

if __name__ == "__main__":
    main()
