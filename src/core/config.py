
import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
SRC_DIR = Path(__file__).resolve().parent.parent

# API Keys
try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / ".env")
except ImportError:
    pass

# API Keys
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
if not GOOGLE_API_KEY:
    # Fallback or strict error? 
    # For now, let's just warn or let it fail later if not found.
    # But usually user wants to ensure it works. 
    # If the user explicitly asked to REMOVE the clear text api, I must not leave it.
    pass


# Data Directories
RESULTS_DIR = BASE_DIR / "results"
SQLMAP_RESULTS_DIR = RESULTS_DIR / "sqlmap_light"
POCS_DIR = BASE_DIR / "pocs"
RUNS_DIR = BASE_DIR / "feedback_runs"
CACHE_DIR = BASE_DIR / "cache_ctx"

# Database
MEMORY_DB_PATH = BASE_DIR / "mem.sqlite3"
RAG_DB_PATH = BASE_DIR / "rag_db_gemini_chunked_v4"
COLLECTION_NAME = "exploit_knowledge_base_gemini_v4"

# Tools Configuration
SQLMAP_BIN = os.environ.get("SQLMAP_BIN", None)
SQLMAP_TIMEOUT_LIGHT = int(os.environ.get("SQLMAP_TIMEOUT_LIGHT", "300"))
SQLMAP_DISCOVERY = os.environ.get("SQLMAP_DISCOVERY", "1") != "0"
SQLMAP_DISCOVERY_LIMIT = int(os.environ.get("SQLMAP_DISCOVERY_LIMIT", "12"))

# Scanning
COMMON_HTTP_PORTS = {
    80, 81, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9080, 9090, 9200, 9300, 9443,
    15672, 5601, 5000, 3000, 7001
}

SERVICE_OVERRIDE = {
    "openresty": "nginx",
    "openresty nginx": "nginx",
    "httpd": "apache httpd",
}

CVE_TO_PRODUCT_OVERRIDE = {
    "CVE-2021-25646": "Apache Druid",
    "CVE-2014-6271": "Apache httpd",
    "CVE-2020-13942": "Apache Unomi"
}

# Ensure directories exist
for d in [RESULTS_DIR, SQLMAP_RESULTS_DIR, POCS_DIR, RUNS_DIR, CACHE_DIR]:
    d.mkdir(exist_ok=True, parents=True)
