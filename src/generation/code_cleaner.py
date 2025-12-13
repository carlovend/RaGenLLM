
import re
from typing import List, Tuple

# Regex Constants
CVE_RE = re.compile(r'\bCVE-?(\d{4})-(\d{4,7})\b', re.I)
CODE_BLOCK_RE = re.compile(r"```(?:\w+)?\s*([\s\S]*?)```", re.M)
INLINE_CMD_RE = re.compile(
    r'(?:^|\n)(?:\$ ?)?(?:curl|wget|touch|nc|python3?|python|java|bash|sh|docker|docker-compose)\b[^\n]{0,400}\n?',
    re.I
)

def normalize_cve(s: str) -> str:
    m = CVE_RE.search(s or "")
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else ""

def find_all_cves(text: str) -> List[str]:
    return [f"CVE-{y}-{n}" for y, n in CVE_RE.findall(text or "")]

def extract_code_snippets(block: str) -> List[str]:
    return CODE_BLOCK_RE.findall(block or "")

def redact_sensitive_commands(code: str) -> str:
    """
    Redact dangerous commands for display purposes.
    """
    code = re.sub(r'Runtime\.getRuntime\(\)\.exec\([^\)]*\)', 'Runtime.getRuntime().exec("<REDACTED_CMD>")', code)
    code = re.sub(r'\b(system|exec|popen)\s*\([^)]*\)', r'\1(<REDACTED>)', code, flags=re.I)
    code = re.sub(r'(curl|wget|nc|bash|sh|docker-compose|docker)\s+[^\\n]+', r'\1 <REDACTED_CMD>', code, flags=re.I)
    return code

def sanitize_code_fences(text: str) -> str:
    """Removes markdown code fences returning raw code."""
    t = text.strip()
    if t.startswith("```"):
        t = t.split("```", 1)[1]
        if "\n" in t:
            t = t.split("\n", 1)[1]
        if "```" in t:
            t = t.rsplit("```", 1)[0]
    return t.strip()
