
import subprocess
import tempfile
import json
import os
from typing import List, Dict, Any

from src.core.logger import get_logger

logger = get_logger(__name__)

class NucleiRunner:
    def scan(self, url: str) -> List[Dict[str, Any]]:
        logger.info(f"Avvio scansione Nuclei su {url}...")
        
        # Create a temporary file for JSON output
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix=".json") as tmp_file:
            json_output_path = tmp_file.name
            
        try:
            # Run Nuclei
            cmd = ["nuclei", "-u", url, "-jsonl", "-o", json_output_path]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            # Parse results
            findings = []
            if os.path.exists(json_output_path):
                with open(json_output_path, "r", encoding="utf-8") as f:
                    for line in f:
                        try:
                            findings.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            return findings
            
        except FileNotFoundError:
            logger.warning("Nuclei non trovato nel PATH. Salto la scansione.")
            return []
        except subprocess.CalledProcessError as e:
            # Nuclei might return non-zero exit code if no findings, but usually 0.
            # If it fails, log stderr (unless it's just 'no results' logic which varies by version)
            if e.returncode != 1: 
                logger.error(f"Errore esecuzione Nuclei: {e.stderr}")
            return []
        except Exception as e:
            logger.error(f"Eccezione generica in NucleiRunner: {e}")
            return []
        finally:
            # Cleanup temp file
            if os.path.exists(json_output_path):
                try:
                    os.remove(json_output_path)
                except OSError:
                    pass
