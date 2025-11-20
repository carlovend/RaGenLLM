# retrieval/embedder.py

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List

from sentence_transformers import SentenceTransformer
import google.generativeai as genai

try:
    from . import config
except ImportError:
    import config


class Embedder(ABC):
    """
    Generic interface that all embedders must implement.
    """

    @abstractmethod
    def embed_query(self, text: str) -> List[float]:
        pass

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        pass


class LocalEmbedder(Embedder):
    """
    Local embedding model using BAAI/bge-m3 via SentenceTransformer.
    """

    def __init__(self, model_name: str = "BAAI/bge-small-en", batch_size: int = 64):
        self.model_name = model_name
        self.batch_size = batch_size
        print(f"[LocalEmbedder] Loading model: {model_name}")
        self.model = SentenceTransformer(model_name)

    def embed_query(self, text: str) -> List[float]:
        vec = self.model.encode(
            text,
            batch_size=1,
            normalize_embeddings=True,
            convert_to_numpy=False,
        )
        return vec.tolist()

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        vectors = self.model.encode(
            texts,
            batch_size=self.batch_size,
            normalize_embeddings=True,
            convert_to_numpy=False,
        )
        return [v.tolist() for v in vectors]


class GeminiEmbedder(Embedder):
    """
    Embedder using Google Gemini API.
    """

    def __init__(self, model_name: str = None):
        self.model_name = model_name or config.GEMINI_EMBEDDING_MODEL
        if not config.GOOGLE_API_KEY:
            raise ValueError("GOOGLE_API_KEY not found in environment variables")
        genai.configure(api_key=config.GOOGLE_API_KEY)
        print(f"[GeminiEmbedder] Initialized with model: {self.model_name}")

    def embed_query(self, text: str) -> List[float]:
        result = genai.embed_content(
            model=self.model_name,
            content=text,
            task_type="retrieval_query"
        )
        return result['embedding']

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        # The API supports passing a list of strings directly
        try:
            result = genai.embed_content(
                model=self.model_name,
                content=texts,
                task_type="retrieval_document"
            )
            return result['embedding']
        except Exception as e:
            print(f"[GeminiEmbedder] Batch embedding failed: {e}")
            # Fallback to sequential if batch fails (e.g. too large)
            embeddings = []
            for text in texts:
                try:
                    res = genai.embed_content(
                        model=self.model_name,
                        content=text,
                        task_type="retrieval_document"
                    )
                    embeddings.append(res['embedding'])
                except Exception as inner_e:
                    print(f"[GeminiEmbedder] Single embedding failed: {inner_e}")
                    # Append zero vector or skip? Better to raise or append zeros.
                    # For now, let's append a zero vector of size 768 (standard) to keep alignment
                    embeddings.append([0.0] * 768) 
            return embeddings
