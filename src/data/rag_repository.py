
try:
    import chromadb
except ImportError:
    chromadb = None

import google.generativeai as genai
import re
import os
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from src.core.config import RAG_DB_PATH, COLLECTION_NAME, GOOGLE_API_KEY
from src.core.logger import get_logger

logger = get_logger(__name__)

# Constants from legacy
EMBEDDING_MODEL_NAME = "models/text-embedding-004"
HARD_BLOCK_EXT = {".toml", ".yml", ".yaml"}
FILENAME_HARD_BLACKLIST = {
    "environments.toml", "environment.toml", "index.md", "index.rst",
    "manifest.toml", "manifest.yaml", "manifest.yml",
    "changelog", "changelog.md", "readme-index.md"
}
NOISY_NAME_PATTERNS = [
    r"\.toml$", r"\.yml$", r"\.yaml$", r"^index\.", r"changelog", r"manifest"
]
PRODUCT_ALIASES: Dict[str, List[str]] = {
    "geoserver": ["geoserver", "geo server", "geo-server", "geoserver org"],
}

# Configure Gemini
if GOOGLE_API_KEY:
    genai.configure(api_key=GOOGLE_API_KEY)

def _norm(s: str) -> str:
    return (s or "").strip().lower()

def _contains_ci(hay: str, needle: str) -> bool:
    return _norm(needle) in _norm(hay)

def _normalize_text_for_alias(s: str) -> str:
    return re.sub(r'[^a-z0-9]+', ' ', _norm(s)).strip()

def _has_blocked_extension(name: str) -> bool:
    name = (name or "").strip().lower()
    _, dot, ext = name.rpartition(".")
    ext = f".{ext}" if dot else ""
    return ext in HARD_BLOCK_EXT

class RagRepository:
    def __init__(self, db_path=str(RAG_DB_PATH), collection_name=COLLECTION_NAME):
        self.db_path = Path(db_path)
        self.collection_name = collection_name
        self.collection = None
        
        if not chromadb:
            logger.error("chromadb module not found.")
            return

        self._load_database()

    def _load_database(self):
        if not self.db_path.exists():
            logger.error(f"DB path not found: {self.db_path}")
            return
        try:
            client = chromadb.PersistentClient(path=str(self.db_path))
            self.collection = client.get_collection(name=self.collection_name)
            logger.info(f"RAG DB loaded from {self.db_path}")
        except Exception as e:
            logger.error(f"Error loading RAG DB: {e}")

    def _get_embedding(self, text: str) -> List[float]:
        try:
            result = genai.embed_content(
                model=EMBEDDING_MODEL_NAME,
                content=text,
                task_type="retrieval_query",
            )
            return result.get("embedding", []) or []
        except Exception as e:
            logger.warning(f"Gemini embedding error: {e}")
            return []

    # --- Product Helpers ---
    def _product_aliases(self, product: str) -> List[str]:
        p = _norm(product)
        aliases = PRODUCT_ALIASES.get(p, [p]) if p else []
        return list({ _normalize_text_for_alias(a) for a in aliases if a })

    def _product_appears(self, text: str, product: str) -> bool:
        if not product: return False
        norm_text = _normalize_text_for_alias(text)
        for alias in self._product_aliases(product):
            if alias and alias in norm_text:
                return True
        return False

    def _should_exclude_by_name(self, meta: Dict[str, Any]) -> bool:
        fname = _norm(meta.get("original_filename", ""))
        if _has_blocked_extension(fname): return True
        if fname in FILENAME_HARD_BLACKLIST: return True
        for pat in NOISY_NAME_PATTERNS:
            if re.search(pat, fname): return True
        return False

    def _filter_chunks_for_cve_and_product(self, items: List[Dict[str, Any]], target_cve: str, product: str) -> List[Dict[str, Any]]:
        if not target_cve and not product:
            return [r for r in items if not self._should_exclude_by_name(r.get("metadata") or {})]

        t_cve = _norm(target_cve)
        filtered = []

        for r in items:
            m = (r.get("metadata") or {})
            if self._should_exclude_by_name(m): continue

            fname = _norm(m.get("original_filename", ""))
            fpath = _norm(m.get("original_path", ""))
            doc = r.get("document", "") or ""
            low_doc = _norm(doc)

            has_cve = bool(t_cve) and (t_cve in fname or t_cve in fpath or t_cve in low_doc)
            has_prod = bool(product) and (self._product_appears(doc, product) or _contains_ci(fpath, product) or _contains_ci(fname, product))

            if target_cve and product:
                if has_cve and has_prod: filtered.append(r)
            elif target_cve:
                if has_cve: filtered.append(r)
            else:
                if has_prod: filtered.append(r)
        
        return filtered or [r for r in items if not self._should_exclude_by_name(r.get("metadata") or {})]

    # --- Scoring & Rerank ---
    def _payload_score(self, text: str, product: str = "", cves: List[str] = None) -> float:
        cves = cves or []
        low = _norm(text)
        score = 0.0
        if ("```" in text) or ("def " in low) or ("class " in low) or ("import " in low): score += 1.0
        if product and product.lower() in low: score += 0.8
        for c in cves:
            if c and _contains_ci(low, c): score += 1.5
        return score

    def _boost_and_rerank(self, results: List[Dict[str, Any]], product: str, cves: List[str]) -> List[Tuple[float, Dict[str, Any]]]:
        boosted = []
        for r in results:
            try:
                base = 1.0 - float(r.get("distance", 1.0))
            except Exception:
                base = 0.0
            
            text = r.get("document", "") or ""
            pscore = self._payload_score(text, product, cves)
            
            # Simplified weighting from legacy
            combined = base + (0.20 * pscore)
            boosted.append((combined, r))
        
        boosted.sort(key=lambda x: x[0], reverse=True)
        return boosted

    # --- Main Retrieval Method ---
    def retrieve_context_for_service(self, service_info: Dict[str, Any], cve: str) -> str:
        if not self.collection:
            return ""

        product = (service_info.get("product") or "").strip()
        version = (service_info.get("version") or "").strip()
        cves = [cve]

        # Build Queries
        queries = []
        if cve:
            queries.extend([cve, f"{cve} exploit", f"{cve} poc", f"{cve} vuln"])
            if product: queries.append(f"{cve} {product}")
        if not queries and product:
             queries = [f"{product} exploit", f"{product} CVE"]

        # Embeddings
        logger.info(f"Generating embeddings for {len(queries)} queries...")
        embeddings = [self._get_embedding(q) for q in queries]
        embeddings = [e for e in embeddings if e]

        if not embeddings:
            return ""

        # Query DB
        try:
            raw = self.collection.query(
                query_embeddings=embeddings,
                n_results=80,
                include=["documents", "metadatas", "distances"]
            )
            
            # Deduplicate
            all_chunks = {}
            for i in range(len(raw["ids"])):
                ids = raw["ids"][i]
                docs = raw["documents"][i]
                metas = raw["metadatas"][i]
                dists = raw["distances"][i]
                for chunk_id, doc, meta, dist in zip(ids, docs, metas, dists):
                    cid = str(chunk_id)
                    if cid not in all_chunks or dist < all_chunks[cid]["distance"]:
                        all_chunks[cid] = {"document": doc, "metadata": meta, "distance": dist}

            if not all_chunks: return ""

            # Filter & Rerank
            unique_results = list(all_chunks.values())
            filtered = self._filter_chunks_for_cve_and_product(unique_results, cve, product)
            boosted = self._boost_and_rerank(filtered, product, cves)

            # Build Context
            take = min(len(boosted), 12)
            context = []
            for score, chunk in boosted[:take]:
                 meta = chunk.get("metadata") or {}
                 header = f"###--- CONTESTO (Score: {score:.2f}) File: {meta.get('original_filename')} ---###"
                 context.append(f"{header}\n{chunk.get('document')}")

            return "\n\n".join(context)

        except Exception as e:
            logger.error(f"Retrieval failed: {e}")
            return ""
