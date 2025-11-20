# retrieval/retriever.py

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb

from retrieval.config import DB_PATH, COLLECTION_NAME
from retrieval import config
from embedder import Embedder, LocalEmbedder, GeminiEmbedder


def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def _extract_cves_from_text(text: str) -> List[str]:
    pattern = r"\bCVE-\d{4}-\d{4,7}\b"
    found = re.findall(pattern, text, flags=re.IGNORECASE)
    return sorted({c.upper() for c in found})


def _is_probably_noise_filename(name: str) -> bool:
    if not name:
        return False
    name = name.lower()
    if any(name.endswith(ext) for ext in (".toml", ".yml", ".yaml")):
        return True
    if "changelog" in name:
        return True
    if name.startswith("index."):
        return True
    return False


@dataclass
class RetrievedChunk:
    id: str
    text: str
    distance: float
    source: str
    original_path: str
    original_filename: str
    cves: List[str]


@dataclass
class RetrievedContext:
    query: str
    chunks: List[RetrievedChunk]
    context_str: str
    debug_info: Dict[str, Any]


class RAGRetriever:
    """
    RAG retriever for RaGenLLM using a local embedding model and ChromaDB.
    """

    def __init__(
        self,
        embedder: Optional[Embedder] = None,
        top_k: int = 32,
        max_chunks: int = 12,
    ):
        if embedder:
            self.embedder = embedder
        elif config.USE_GEMINI:
            self.embedder = GeminiEmbedder()
        else:
            self.embedder = LocalEmbedder()

        self.top_k = top_k
        self.max_chunks = max_chunks

        self._client = chromadb.PersistentClient(path=str(DB_PATH))
        self._collection = self._get_collection()

    def _get_collection(self):
        try:
            coll = self._client.get_collection(name=COLLECTION_NAME)
        except Exception as e:
            raise RuntimeError(
                f"Unable to open ChromaDB collection '{COLLECTION_NAME}': {e}"
            )
        return coll

    # -------------------------
    # Public API
    # -------------------------

    def retrieve_for_service(
        self,
        service: Dict[str, Any],
        target_cve: Optional[str] = None,
        extra_hints: Optional[str] = None,
    ) -> RetrievedContext:
        """
        Given a scanned service + optional CVE, retrieve a compact evidence pack.
        """
        query_str = self._build_query_string(service, target_cve, extra_hints)
        query_emb = self.embedder.embed_query(query_str)

        raw = self._collection.query(
            query_embeddings=[query_emb],
            n_results=self.top_k,
            include=["documents", "metadatas", "distances"],
        )

        chunks = self._postprocess_results(raw, target_cve, service)
        context_str = self._build_context_string(chunks)

        debug_info = {
            "query": query_str,
            "target_cve": target_cve,
            "num_raw_results": len(raw.get("ids", [[]])[0]) if raw.get("ids") else 0,
            "num_final_chunks": len(chunks),
        }

        return RetrievedContext(
            query=query_str,
            chunks=chunks,
            context_str=context_str,
            debug_info=debug_info,
        )

    # -------------------------
    # Query building
    # -------------------------

    def _build_query_string(
        self,
        service: Dict[str, Any],
        target_cve: Optional[str],
        extra_hints: Optional[str],
    ) -> str:
        """
        Build a textual query from service info (CVE, product, version, banners).
        """
        parts: List[str] = []

        if target_cve:
            parts.append(target_cve)

        product = (
            service.get("normalized_product")
            or service.get("product")
            or service.get("guessed_product")
        )
        version = service.get("version") or ""
        if product:
            parts.append(str(product))
        if version:
            parts.append(str(version))

        service_cves = service.get("cves") or []
        for c in service_cves:
            if isinstance(c, str):
                parts.append(c)

        name = service.get("name") or ""
        fingerprint = service.get("fingerprint") or ""
        if name:
            parts.append(str(name))
        if fingerprint:
            parts.append(str(fingerprint))

        if extra_hints:
            parts.append(extra_hints)

        base = " ".join(str(p) for p in parts if p).strip()
        if not base:
            base = "web application exploit proof-of-concept"

        return base

    # -------------------------
    # Post-processing
    # -------------------------

    def _postprocess_results(
        self,
        raw: Dict[str, Any],
        target_cve: Optional[str],
        service: Dict[str, Any],
    ) -> List[RetrievedChunk]:
        ids_lists = raw.get("ids") or [[]]
        docs_lists = raw.get("documents") or [[]]
        metas_lists = raw.get("metadatas") or [[]]
        dist_lists = raw.get("distances") or [[]]

        if not ids_lists or not ids_lists[0]:
            return []

        ids = ids_lists[0]
        docs = docs_lists[0]
        metas = metas_lists[0]
        dists = dist_lists[0]

        target_cve_norm = _norm(target_cve) if target_cve else ""
        prod_norm = _norm(
            service.get("normalized_product")
            or service.get("product")
            or service.get("guessed_product")
        )

        items: List[Dict[str, Any]] = []
        for chunk_id, text, meta, dist in zip(ids, docs, metas, dists):
            meta = meta or {}
            original_path = meta.get("original_path") or meta.get("path") or ""
            original_filename = meta.get("original_filename") or Path(original_path).name
            source = meta.get("source") or meta.get("origin") or "unknown"

            cves_in_meta: List[str] = []
            raw_cves = meta.get("cves") or ""
            if isinstance(raw_cves, str) and raw_cves.strip():
                cves_in_meta.extend([c.strip() for c in raw_cves.split(",") if c.strip()])

            cves_in_text = _extract_cves_from_text(text or "")
            all_cves = sorted({c.upper() for c in cves_in_meta + cves_in_text})

            base_score = 1.0 / (1.0 + float(dist))
            score = base_score

            has_target_cve = False
            if target_cve_norm:
                for c in all_cves:
                    if _norm(c) == target_cve_norm:
                        has_target_cve = True
                        break
            if has_target_cve:
                score += 1.5

            if prod_norm:
                fp = f"{original_path} {original_filename} {_norm(text[:200])}"
                if prod_norm in fp:
                    score += 0.8

            if _is_probably_noise_filename(original_filename):
                score -= 1.0

            items.append(
                dict(
                    id=chunk_id,
                    text=text,
                    distance=float(dist),
                    score=score,
                    source=source,
                    original_path=original_path,
                    original_filename=original_filename,
                    cves=all_cves,
                )
            )

        best_by_doc: Dict[str, Dict[str, Any]] = {}
        for it in items:
            key = it["original_path"] or it["id"]
            prev = best_by_doc.get(key)
            if not prev or it["score"] > prev["score"]:
                best_by_doc[key] = it

        deduped = list(best_by_doc.values())
        deduped.sort(key=lambda x: x["score"], reverse=True)

        top = deduped[: self.max_chunks]

        return [
            RetrievedChunk(
                id=it["id"],
                text=it["text"],
                distance=it["distance"],
                source=it["source"],
                original_path=it["original_path"],
                original_filename=it["original_filename"],
                cves=it["cves"],
            )
            for it in top
        ]

    def _build_context_string(self, chunks: List[RetrievedChunk]) -> str:
        """
        Build a human- and LLM-friendly context block from ranked chunks.
        """
        if not chunks:
            return "No external exploit evidence was retrieved from the knowledge base."

        parts: List[str] = []
        for idx, ch in enumerate(chunks, start=1):
            header = (
                f"[EVIDENCE #{idx}] "
                f"source={ch.source} "
                f"path={ch.original_path} "
                f"cves={','.join(ch.cves) if ch.cves else 'none'}"
            )
            parts.append(header)
            parts.append(ch.text.strip())
            parts.append("")

        return "\n".join(parts).strip()
