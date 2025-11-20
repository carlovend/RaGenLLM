# retrieval/chunking.py

import re
from pathlib import Path
from typing import List, Dict, Any


# --- Filetype groups ---

CODE_EXT = {".py", ".rb", ".sh", ".php", ".c", ".cpp", ".go", ".js", ".ps1"}
TEXT_EXT = {".md", ".txt", ".rst"}
CONFIG_EXT = {".yml", ".yaml", ".json", ".toml"}

MAX_CODE_CHUNK = 2000        # codice deve restare leggibile
MAX_TEXT_CHUNK = 1500        # paragrafi "naturali"
MAX_README_CHUNK = 4000      # file README più lunghi
MAX_OVERLAP = 60


def extract_cves(text: str) -> List[str]:
    pattern = r"\bCVE-\d{4}-\d{4,7}\b"
    found = re.findall(pattern, text, flags=re.IGNORECASE)
    return sorted({c.upper() for c in found})


def chunk_code(content: str, max_len: int = MAX_CODE_CHUNK) -> List[str]:
    """
    Chunking molto semplice per codice:
    - mantiene blocchi compatti
    - spezza solo se strettamente necessario
    """
    if len(content) <= max_len:
        return [content]

    lines = content.splitlines()
    chunks = []
    buf = []

    current_len = 0
    for line in lines:
        if current_len + len(line) < max_len:
            buf.append(line)
            current_len += len(line)
        else:
            chunks.append("\n".join(buf))
            buf = [line]
            current_len = len(line)

    if buf:
        chunks.append("\n".join(buf))

    return chunks


def chunk_text(content: str, max_len: int = MAX_TEXT_CHUNK, overlap: int = MAX_OVERLAP) -> List[str]:
    """
    Chunking adattivo per testi tecnici:
    - separa per paragrafi
    - applica ma leggermente overlapping
    """
    content = content.strip()
    if not content:
        return []

    paragraphs = [p.strip() for p in content.split("\n\n") if p.strip()]
    result = []

    for para in paragraphs:
        if len(para) <= max_len:
            result.append(para)
        else:
            for i in range(0, len(para), max_len - overlap):
                piece = para[i:i + max_len]
                if len(piece) > 40:
                    result.append(piece)

    return result


def chunk_file(path: Path, content: str) -> List[Dict[str, Any]]:
    """
    Chunking universale basato su estensione + contenuto.
    Restituisce una lista di dict:
        {
          "text": "...",
          "meta": {...}
        }
    """
    suffix = path.suffix.lower()
    cves = extract_cves(content)

    if suffix in CODE_EXT:
        raw_chunks = chunk_code(content)
    elif suffix in TEXT_EXT:
        raw_chunks = chunk_text(content, MAX_TEXT_CHUNK)
    elif suffix in CONFIG_EXT:
        raw_chunks = chunk_text(content, max_len=1200)
    elif path.name.lower().startswith("readme"):
        raw_chunks = chunk_text(content, MAX_README_CHUNK)
    else:
        # fallback generico
        raw_chunks = chunk_text(content, MAX_TEXT_CHUNK)

    chunks = []
    for idx, ch in enumerate(raw_chunks):
        chunks.append(
    {
        "text": ch,
        "meta": {
            "chunk_index": int(idx),
            "original_filename": path.name,
            "original_path": str(path),
            "source": infer_source(path),
            "cves": ",".join(cves) if cves else "",
        },
    }
)


    return chunks


def infer_source(path: Path) -> str:
    """
    Determina la sorgente del file:
    - exploitdb
    - vulhub
    - metasploit
    - custom
    """
    p = str(path).lower()
    if "exploitdb" in p:
        return "exploitdb"
    if "vulhub" in p:
        return "vulhub"
    if "metasploit" in p:
        return "metasploit"
    return "custom"
