
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class Vulnerability:
    id: str
    severity: str = "unknown"
    description: str = ""
    # meta info from nuclei/nmap
    references: List[str] = field(default_factory=list)

@dataclass
class ServiceInfo:
    ip: str
    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = "unknown"
    version: str = ""
    cpes: List[str] = field(default_factory=list)
    
    # Enhanced attributes
    normalized_product: Optional[str] = None
    confidence: int = 0
    fingerprint: Optional[str] = None
    http_probe: Dict[str, Any] = field(default_factory=dict)
    
    # Findings
    cves: List[str] = field(default_factory=list)
    nuclei_findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # User feedback
    user_confirmed_product: Optional[str] = None
    user_overridden: bool = False

    def get_target_url(self) -> str:
        scheme = "https" if "ssl" in self.name or self.port in {443, 8443, 9443} else "http"
        return f"{scheme}://{self.ip}:{self.port}"
