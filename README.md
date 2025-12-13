# RaGenLLM (Refactored)

**Retrieval-Augmented LLM Framework for Automated Proof-of-Concept Generation**

RaGenLLM is a modular framework designed to automate the detection and verification of vulnerabilities in web applications. It combines traditional scanning tools (Nmap, Nuclei) with Retrieval-Augmented Generation (RAG) and Local LLMs (Ollama) to synthesize and test Proof-of-Concept (PoC) exploits in a controlled feedback loop.

## Key Features

*   ** Automated Scanning**: Integrates **Nmap** (service discovery) and **Nuclei** (vulnerability scanning) to identify targets.
*   ** RAG-Powered Generation**: Uses **Google Gemini Embeddings** (or local BGE-M3) to retrieve high-quality context from a curated exploit knowledge base (ChromaDB).
*   ** LLM-based Synthesis**: Generates customized Python PoC scripts using **DeepSeek Coder** (via Ollama).
*   ** Self-Refinement Loop**: Executes generated PoCs, analyzes stdout/stderr, and iteratively refines the code if it fails (using the error output as feedback).
*   ** Smart Retrieval**: Features multi-query generation, advanced re-ranking (payload boosting), and key payload extraction to ensure the LLM gets the exact snippets it needs.

## Architecture

```
RaGenLLM/
├── scanner/          # Nmap and Nuclei scanning logic
├── retrieval/        # RAG implementation (ChromaDB, Gemini Embeddings, Indexing)
├── refinement/       # Execution engine and feedback loop (Executor, Memory)
├── results/          # Output directory for logs, PoCs, and scan reports
├── oldcode/          # Legacy reference code (ignored)
├── main.py           # Main entry point CLI
└── .env              # Configuration (API Keys)
```

## Requirements

*   **Python 3.10+**
*   **Ollama**: Running locally with `deepseek-coder-v2:16b` (or similar).
*   **Google API Key**: For Gemini Embeddings (optional but recommended for best performance).
*   **Tools**: `nmap`, `nuclei` installed and in PATH.

### Python Dependencies
```bash
pip install -r requirements.txt
# Key deps: chromadb, google-generativeai, python-dotenv, requests, rich
```

## Setup

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/RaGenLLM.git
    cd RaGenLLM
    ```

2.  **Configure Environment**:
    Create a `.env` file in the root directory:
    ```ini
    GOOGLE_API_KEY=your_google_api_key_here
    # USE_GEMINI=true (default)
    ```

3.  **Build the Knowledge Base**:
    Index your exploit documents (Markdown/Text) into ChromaDB:
    ```bash
    python retrieval/build_db.py
    ```

## Usage

### Basic Scan & RAG Generation
Run the full pipeline: scan a target, retrieve context for findings, and generate/verify PoCs.

```bash
python main.py --ip <TARGET_IP> --ports <PORTS> --rag
```

**Example:**
```bash
python main.py --ip 127.0.0.1 --ports 3000 --rag
```

### Flags
*   `--ip`: Target IP address.
*   `--ports`: Target ports (comma-separated or range).
*   `--rag`: Enable the Retrieval-Augmented Generation and Refinement stage.
*   `--fast`: Skip heavy scans (Nuclei/Nmap full) and do a quick check.
*   `--no-nuclei`: Skip Nuclei scanning.

## How it Works
1.  **Scan**: The tool identifies open ports and running services.
2.  **Identify**: It matches services to CVEs or Nuclei templates.
3.  **Retrieve**: For each finding, it queries the Vector DB for "Key Payloads" and exploit guides.
4.  **Generate**: It prompts the Local LLM to write a verification script.
5.  **Refine**: It runs the script. If it fails, it feeds the error back to the LLM for correction (up to 3 attempts).
6.  **Report**: Successful PoCs are saved to `results/pocs/`.

## Disclaimer
This tool is for **educational and research purposes only**. Use it only on systems you own or have explicit permission to test.
