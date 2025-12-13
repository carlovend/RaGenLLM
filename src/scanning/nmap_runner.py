
import nmap
import re
from typing import List, Dict, Any

from src.core.logger import get_logger
from src.scanning.utils import normalize_service

logger = get_logger(__name__)

class NmapRunner:
    def scan(self, ip: str, ports: str) -> List[Dict[str, Any]]:
        logger.info(f"Avvio scansione Nmap su {ip}:{ports}...")
        nm = nmap.PortScanner()
        results = []
        try:
            # Arguments: Service Version, No Ping, Vulners Script
            nm.scan(hosts=ip, ports=ports, arguments='-sV -Pn --script vulners')
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto]:
                        serv = nm[host][proto][port]
                        script_field = serv.get("script", {})
                        if not isinstance(script_field, dict):
                            script_field = {}
                            
                        # Extract CVEs from vulners output
                        cves_found = re.findall(r"(CVE-\d{4}-\d+)", script_field.get("vulners", "") or "")
                        
                        svc = {
                            "ip": host,
                            "port": port,
                            "protocol": proto,
                            "name": serv.get("name") or "",
                            "product": serv.get("product") or serv.get("name") or "",
                            "version": serv.get("version") or "",
                            "extrainfo": serv.get("extrainfo") or "",
                            "cpe": serv.get("cpe", []),
                            "cves": list(set(cves_found)),
                            "nuclei_findings": []
                        }
                        
                        # Apply normalization (heuristics, http probing, etc.)
                        svc = normalize_service(svc)
                        results.append(svc)
            return results
        except Exception as e:
            logger.error(f"Errore durante scansione Nmap: {e}")
            return []
