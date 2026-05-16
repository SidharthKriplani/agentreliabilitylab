from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
"""
AgentReliabilityLab — Hybrid Retrieval + Reranking
BM25 (sparse) + ChromaDB (dense) → merge → cross-encoder reranker → top-k chunks.
"""
import pickle
import sys
from pathlib import Path
from typing import Optional

import chromadb
from chromadb.utils import embedding_functions

import config

_BM25_PATH = Path(config.CHROMA_PERSIST_DIR) / "bm25_corpus.pkl"

# ── Lazy-loaded singletons ────────────────────────────────────────────────────
_chroma_collection = None
_bm25_data: Optional[dict] = None
_reranker = None


def _get_collection():
    global _chroma_collection
    if _chroma_collection is not None:
        return _chroma_collection
    client = chromadb.PersistentClient(path=config.CHROMA_PERSIST_DIR)
    ef     = embedding_functions.SentenceTransformerEmbeddingFunction(
                 model_name=config.EMBEDDING_MODEL)
    _chroma_collection = client.get_collection(
        name=config.CHROMA_COLLECTION,
        embedding_function=ef,
    )
    return _chroma_collection


def _get_bm25():
    global _bm25_data
    if _bm25_data is not None:
        return _bm25_data
    if not _BM25_PATH.exists():
        return None
    with open(_BM25_PATH, "rb") as f:
        _bm25_data = pickle.load(f)
    return _bm25_data


def _get_reranker():
    global _reranker
    if _reranker is not None:
        return _reranker
    try:
        from sentence_transformers import CrossEncoder
        _reranker = CrossEncoder(config.RERANKER_MODEL)
    except Exception as e:
        print(f"[retriever] Reranker load failed: {e}", file=sys.stderr)
        _reranker = None
    return _reranker


def _dense_retrieve(query: str, k: int) -> list[dict]:
    try:
        col     = _get_collection()
        results = col.query(query_texts=[query], n_results=k)
        chunks  = []
        for i, doc in enumerate(results["documents"][0]):
            meta = results["metadatas"][0][i]
            dist = results["distances"][0][i] if results.get("distances") else 0.5
            chunks.append({
                "chunk_id":  meta.get("chunk_id", f"dense_{i}"),
                "source":    meta.get("source",   "unknown"),
                "text":      doc,
                "score":     float(1.0 - dist),   # cosine distance → similarity
                "retrieval": "dense",
            })
        return chunks
    except Exception as e:
        print(f"[retriever] Dense retrieval error: {e}", file=sys.stderr)
        return []


def _bm25_retrieve(query: str, k: int) -> list[dict]:
    data = _get_bm25()
    if not data:
        return []
    try:
        tokens = query.lower().split()
        scores = data["bm25"].get_scores(tokens)
        top_idx = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
        results = []
        for idx in top_idx:
            c = data["chunks"][idx]
            results.append({
                "chunk_id":  c["chunk_id"],
                "source":    c["source"],
                "text":      c["text"],
                "score":     float(scores[idx]),
                "retrieval": "bm25",
            })
        return results
    except Exception as e:
        print(f"[retriever] BM25 error: {e}", file=sys.stderr)
        return []


def _rerank(query: str, candidates: list[dict], top_k: int) -> list[dict]:
    reranker = _get_reranker()
    if not reranker or not candidates:
        return candidates[:top_k]
    try:
        pairs  = [(query, c["text"]) for c in candidates]
        scores = reranker.predict(pairs)
        ranked = sorted(zip(scores, candidates), key=lambda x: x[0], reverse=True)
        for score, chunk in ranked:
            chunk["score"] = float(score)
            chunk["retrieval"] = "hybrid"
        return [c for _, c in ranked[:top_k]]
    except Exception as e:
        print(f"[retriever] Reranker error: {e}", file=sys.stderr)
        return candidates[:top_k]


def retrieve_threat_chunks(query: str, top_k: int = 8) -> list[dict]:
    """
    Hybrid retrieval: BM25 + dense → deduplicate → rerank → top_k.
    """
    k_each  = max(top_k, 12)   # fetch extra candidates before reranking
    dense   = _dense_retrieve(query, k_each)
    sparse  = _bm25_retrieve(query, k_each)

    # Merge — deduplicate by chunk_id, keep best score
    seen: dict[str, dict] = {}
    for c in dense + sparse:
        cid = c["chunk_id"]
        if cid not in seen or c["score"] > seen[cid]["score"]:
            seen[cid] = c
    candidates = list(seen.values())

    return _rerank(query, candidates, top_k)
