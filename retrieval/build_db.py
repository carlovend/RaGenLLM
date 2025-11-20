from pathlib import Path
from indexer import Indexer
from embedder import LocalEmbedder, GeminiEmbedder
import config

paths = [
    Path("/Users/carlovenditto/Desktop/TesiAPI/exploitdb"),
    Path("/Users/carlovenditto/Desktop/tesiprogetto/vulhub"),
    Path("/Users/carlovenditto/Desktop/TesiAPI/metasploit-framework/modules/exploits"),
]

if config.USE_GEMINI:
    embedder = GeminiEmbedder()
else:
    embedder = LocalEmbedder()
indexer = Indexer(paths,embedder)
indexer.index()
