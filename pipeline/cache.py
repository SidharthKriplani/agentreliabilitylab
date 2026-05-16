from __future__ import annotations
"""
AgentReliabilityLab — Extraction Cache
SHA-256(alert_text + node_name) → Redis or in-memory fallback.
Same architecture as LendFlow — 24h TTL, zero PII in cache.
"""
import hashlib
import json
import os
from typing import Optional

REDIS_URL    = os.environ.get("REDIS_URL", "")
CACHE_TTL    = int(os.environ.get("CACHE_TTL_SECONDS", 86400))
CACHE_PREFIX = "arl:cache:"

_redis_client = None
_memory_cache: dict = {}


def _get_redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if not REDIS_URL:
        return None
    try:
        import redis
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True,
                                        socket_timeout=0.5)
        _redis_client.ping()
        return _redis_client
    except Exception:
        _redis_client = None
        return None


def _make_key(text: str, node: str) -> str:
    payload = f"{node}::{text}".encode("utf-8")
    return f"{CACHE_PREFIX}{hashlib.sha256(payload).hexdigest()}"


def get_cached(text: str, node: str) -> Optional[dict]:
    key = _make_key(text, node)
    r   = _get_redis()
    try:
        raw = r.get(key) if r else _memory_cache.get(key)
        if raw:
            return json.loads(raw)
    except Exception:
        pass
    return None


def set_cached(text: str, node: str, data: dict, _extras: dict) -> None:
    key     = _make_key(text, node)
    payload = json.dumps(data)
    r       = _get_redis()
    try:
        if r:
            r.setex(key, CACHE_TTL, payload)
        else:
            _memory_cache[key] = payload
    except Exception:
        pass


def cache_stats() -> dict:
    r = _get_redis()
    return {
        "backend":        "redis" if r else "memory",
        "memory_entries": len(_memory_cache) if not r else None,
        "ttl_seconds":    CACHE_TTL,
    }
