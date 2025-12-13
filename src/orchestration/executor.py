
import subprocess
from typing import Tuple
from src.core.logger import get_logger

logger = get_logger(__name__)

class Executor:
    @staticmethod
    def run_poc(file_path: str, timeout_s: int = 30) -> Tuple[int, str, str]:
        """Runs the python file in a subprocess."""
        cmd = ["python3", file_path]
        try:
            logger.info(f"Executing PoC: {file_path}")
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired:
            return 124, "", "Timeout expired"
        except Exception as e:
            return 255, "", str(e)
