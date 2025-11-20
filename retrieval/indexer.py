# retrieval/indexer.py

from __future__ import annotations
from pathlib import Path
from typing import List

import chromadb
from tqdm import tqdm

from config import (
    DB_PATH,
    COLLECTION_NAME,
    API_BATCH_SIZE,
    CHROMA_BATCH_SIZE,
)
from embedder import Embedder, LocalEmbedder
from chunking import chunk_file, CODE_EXT, TEXT_EXT, CONFIG_EXT


EXCLUDED_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    "venv",
    "env",
}

MIN_FILE_SIZE = 10
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


def is_text_like(path: Path) -> bool:
    suffix = path.suffix.lower()
    return suffix in CODE_EXT or suffix in TEXT_EXT or suffix in CONFIG_EXT


class Indexer:
    """
    Fast and clean indexing using local embeddings (bge-m3)
    with batch-embedding and batch-add to ChromaDB.
    """

    def __init__(self, paths: List[Path], embedder: Embedder):
        self.paths = paths
        self.embedder = embedder
        self.client = chromadb.PersistentClient(path=str(DB_PATH))

        try:
            self.client.delete_collection(COLLECTION_NAME)
        except Exception:
            pass

        self.collection = self.client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )

    def index(self):
        # 1. Collect candidate files
        all_files = []
        for root in self.paths:
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                if any(part in EXCLUDED_DIRS for part in path.parts):
                    continue
                all_files.append(path)

        print(f"[Indexer] Found {len(all_files)} files.\n")

        buffer_texts = []
        buffer_metas = []
        buffer_ids = []
        total_chunks = 0

        # 2. Process files
        for path in tqdm(all_files, desc="Indexing files"):
            try:
                st = path.stat()
            except OSError:
                continue

            if st.st_size < MIN_FILE_SIZE or st.st_size > MAX_FILE_SIZE:
                continue

            if not is_text_like(path):
                continue

            try:
                content = path.read_text(errors="ignore")
            except Exception:
                continue

            chunks = chunk_file(path, content)

            for ch in chunks:
                text = ch["text"]
                meta = dict(ch["meta"])

                # enforce “string-only” metadata for Chroma
                if isinstance(meta.get("cves"), list):
                    meta["cves"] = ",".join(meta["cves"])

                chunk_id = f"{path}:{meta['chunk_index']}"

                buffer_texts.append(text)
                buffer_metas.append(meta)
                buffer_ids.append(chunk_id)

            total_chunks += len(chunks)

            # flush if batch full
            if len(buffer_texts) >= CHROMA_BATCH_SIZE:
                self._flush_batch(buffer_texts, buffer_metas, buffer_ids)

        # final flush
        if buffer_texts:
            self._flush_batch(buffer_texts, buffer_metas, buffer_ids)

        print(f"\n[Indexing Completed] Total chunks indexed: {total_chunks}")

    def _flush_batch(self, texts, metas, ids):
        # batch embedding
        embeddings = []
        for i in range(0, len(texts), API_BATCH_SIZE):
            batch = texts[i:i+API_BATCH_SIZE]
            embeddings.extend(self.embedder.embed_batch(batch))

        # batch write to chroma
        self.collection.add(
            documents=list(texts),
            metadatas=list(metas),
            ids=list(ids),
            embeddings=list(embeddings),
        )

        # clear buffers
        texts.clear()
        metas.clear()
        ids.clear()
