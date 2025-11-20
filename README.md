# RaGenLLM  (REFACTOR IN PROGRESS - CODE NOT COMPLETE)
Retrieval-Augmented LLM Framework for Automated Proof-of-Concept Generation

RaGenLLM is a modular framework that combines vulnerability scanning, retrieval-augmented generation (RAG), and local large language models (LLMs) to automatically synthesize and verify Proof-of-Concept (PoC) exploits in controlled environments.  
The system integrates scanning (Nmap/Nuclei), context retrieval from curated exploit knowledge bases, LLM-based PoC generation, sandboxed execution, and a bounded refinement loop to improve reliability and reproducibility.

## Overview

RaGenLLM provides:
- Retrieval-augmented grounding to reduce hallucinations in exploit synthesis  
- Automated PoC generation using a local code-oriented LLM  
- Isolated and instrumented sandbox execution  
- A structured feedback and refinement mechanism  
- Full logging for reproducibility and auditability  

This project accompanies the research work on automated and safe PoC generation using LLMs and RAG techniques.

## Repository Structure

```
RaGenLLM/
├── scanner/          # Nmap / Nuclei integration
├── retrieval/        # RAG retriever and vector store
├── generator/        # Prompt builder and PoC generator
├── executor/         # Sandbox executor and safety filters
├── refinement/       # Feedback loop for iterative correction
├── utils/            # Logging, config, helpers
└── cli/              # Command-line entrypoints
```

## Requirements

- Python 3.10+
- Docker (for sandboxed execution)
- Ollama (or another local LLM backend)
- ChromaDB (vector store)
- Nmap and Nuclei installed locally

## Status

RaGenLLM is under active development and currently in the refactoring and stabilization phase.
More documentation, examples, and tests will be added in future updates.
