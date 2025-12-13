
from typing import List, Dict, Any, Protocol

class Scanner(Protocol):
    def scan(self, target: str) -> List[Dict[str, Any]]:
        ...
