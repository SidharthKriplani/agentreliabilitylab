from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
"""
AgentReliabilityLab — Threat Intel Indexer
Chunks MITRE ATT&CK / NIST CSF / CISA advisory docs →
  sentence-transformers embeddings → ChromaDB (dense)
  BM25 corpus (sparse)  — both persisted for hybrid retrieval.
"""
import hashlib
import json
import os
import pickle
import sys
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions
from rank_bm25 import BM25Okapi

import config

DOCS_DIR   = Path(__file__).parent / "threat_docs"
BM25_PATH  = Path(config.CHROMA_PERSIST_DIR) / "bm25_corpus.pkl"
CHUNK_SIZE = 400   # characters
OVERLAP    = 80

_SOURCES = {
    "mitre_attack_excerpts.txt":     "mitre_attack",
    "nist_csf_controls.txt":         "nist_csf",
    "cisa_advisories.txt":           "cisa_advisories",
}


def _chunk_text(text: str, source: str) -> list[dict]:
    chunks = []
    start  = 0
    idx    = 0
    while start < len(text):
        end   = min(start + CHUNK_SIZE, len(text))
        chunk = text[start:end].strip()
        if chunk:
            cid = hashlib.md5(f"{source}::{idx}".encode()).hexdigest()[:12]
            chunks.append({
                "chunk_id": cid,
                "source":   source,
                "text":     chunk,
            })
            idx += 1
        start += CHUNK_SIZE - OVERLAP
    return chunks


def build_index() -> None:
    os.makedirs(config.CHROMA_PERSIST_DIR, exist_ok=True)

    # ── ChromaDB client ───────────────────────────────────────────────────
    client = chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)
    ef     = embedding_functions.SentenceTransformerEmbeddingFunction(
                 model_name=config.EMBEDDING_MODEL)

    try:
        client.delete_collection(config.CHROMA_COLLECTION)
    except Exception:
        pass
    collection = client.create_collection(
        name=config.CHROMA_COLLECTION,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    all_chunks: list[dict] = []

    for filename, source_name in _SOURCES.items():
        fpath = DOCS_DIR / filename
        if not fpath.exists():
            print(f"[indexer] WARNING: {fpath} not found — skipping", file=sys.stderr)
            continue
        text   = fpath.read_text(encoding="utf-8")
        chunks = _chunk_text(text, source_name)
        all_chunks.extend(chunks)
        print(f"[indexer] {source_name}: {len(chunks)} chunks")

    if not all_chunks:
        print("[indexer] ERROR: no chunks to index!", file=sys.stderr)
        sys.exit(1)

    # Batch upsert into ChromaDB
    BATCH = 64
    for i in range(0, len(all_chunks), BATCH):
        batch = all_chunks[i:i + BATCH]
        collection.upsert(
            ids        = [c["chunk_id"]  for c in batch],
            documents  = [c["text"]      for c in batch],
            metadatas  = [{"source": c["source"], "chunk_id": c["chunk_id"]}
                          for c in batch],
        )

    # ── BM25 corpus ───────────────────────────────────────────────────────
    tokenised = [c["text"].lower().split() for c in all_chunks]
    bm25      = BM25Okapi(tokenised)

    with open(BM25_PATH, "wb") as f:
        pickle.dump({"bm25": bm25, "chunks": all_chunks}, f)

    print(f"[indexer] Done. {len(all_chunks)} chunks indexed into "
          f"ChromaDB collection '{config.CHROMA_COLLECTION}'")
    print(f"[indexer] BM25 corpus saved to {BM25_PATH}")


if __name__ == "__main__":
    build_index()
