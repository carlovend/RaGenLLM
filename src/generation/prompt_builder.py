
from typing import Dict, Any

class PromptBuilder:
    @staticmethod
    def build_verification_prompt(context: str, service_info: Dict[str, Any]) -> str:
        host = service_info.get("ip", "127.0.0.1")
        port = service_info.get("port", 80)
        
        return f"""
You are an expert security researcher. Write a Python script `poc.py` to VERIFY if the target is vulnerable to the CVEs described in the context.

Target:
- HOST = "{host}"
- PORT = {port}

Technical Context (Payloads & Paths):
---
{context}
---

Instructions:
1. **Aggressive Verification**: Don't just check version numbers. Try to Trigger the vulnerability.
   - If it's an LFI, try to read /etc/passwd or win.ini.
   - If it's an RCE, try to run `id` or `whoami` and capture output.
   - If it's an Auth Bypass, try to access restricted endpoints.
2. **Requirements**:
   - Use `requests` library if helpful (it is installed).
   - If `requests` fails, fallback to `urllib` or `socket` only if strictly necessary.
   - Use a timeout of 10s.
   - DISABLE SSL WARNINGS (urllib3.disable_warnings).
3. **Output**:
   - Print "VULNERABLE" or "POSSIBLE VULNERABILITY" if the exploit works.
   - Print the output of the command or the leaked file content if successful.
4. **Resilience**:
   - Handle connection errors gracefully (try/except).

Return ONLY the raw Python code. No markdown fences.
"""

    @staticmethod
    def build_fix_prompt(distilled_context: str, last_code: str, last_stdout: str, last_stderr: str) -> str:
        return f"""
{distilled_context}

-----
PREVIOUS ERROR (tail):
{last_stderr[-800:]}

PREVIOUS STDOUT (tail):
{last_stdout[-400:]}

PREVIOUS CODE:
```python
{last_code}
```
REQUIREMENT: Fix the code. Keep same HOST/PORT. You can use `requests`. Return ONLY Python source.
-----
"""
