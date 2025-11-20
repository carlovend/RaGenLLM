# retrieval/config.py

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Where ChromaDB will live
DB_PATH = Path("./rag_vector_db")

COLLECTION_NAME = "exploit_knowledge_base_bge_m3"

# Local embedding model
EMBEDDER_MODEL = "BAAI/bge-m3"

# Google Gemini API Key
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Toggle for using Gemini Embeddings
USE_GEMINI = True
GEMINI_EMBEDDING_MODEL = "models/text-embedding-004"

# batch sizes (tunable)
API_BATCH_SIZE = 100
CHROMA_BATCH_SIZE = 4000
