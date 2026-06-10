"""
threat_cache.py — CyberSentinel v2
Caches threat intel results to avoid redundant API calls.
Uses in-memory dict by default. Drop-in Redis upgrade path included.

To use Redis: set REDIS_URL in .env
"""

import json
import os
import time
import asyncio
from typing import Optional


REDIS_URL = os.getenv("REDIS_URL")


class ThreatCache:
    """
    LRU-style cache for threat intel results (VirusTotal, URLScan, WHOIS).
    
    Default: In-memory dict (good for single-process deployments).
    Production: Switch to Redis by setting REDIS_URL.
    
    Cache key format: threat:{md5(target)}
    Default TTL: 1 hour for clean results, 24 hours for malicious results.
    """

    def __init__(self):
        if REDIS_URL:
            self._backend = "redis"
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(REDIS_URL, decode_responses=True)
            except ImportError:
                print("[ThreatCache] redis package not installed — falling back to memory cache")
                self._backend = "memory"
                self._store = {}
        else:
            self._backend = "memory"
            self._store = {}  # key -> {"value": ..., "expires_at": float}
            self._max_size = 1000  # cap memory usage

    async def get(self, key: str) -> Optional[dict]:
        """Retrieve cached result. Returns None on miss or expiry."""
        cache_key = self._make_key(key)

        if self._backend == "redis":
            try:
                raw = await self._redis.get(cache_key)
                return json.loads(raw) if raw else None
            except Exception:
                return None
        else:
            entry = self._store.get(cache_key)
            if not entry:
                return None
            if time.time() > entry["expires_at"]:
                del self._store[cache_key]
                return None
            return entry["value"]

    async def set(self, key: str, value: dict, ttl: int = 3600):
        """Cache a result with TTL (seconds)."""
        cache_key = self._make_key(key)

        # Malicious results cached longer (they're still malicious tomorrow)
        if isinstance(value, dict):
            level = value.get("composite_score", {}).get("level") or value.get("verdict") or ""
            if level in ("CRITICAL", "HIGH", "MALICIOUS"):
                ttl = 86400  # 24 hours

        if self._backend == "redis":
            try:
                await self._redis.setex(cache_key, ttl, json.dumps(value))
            except Exception:
                pass
        else:
            # Evict oldest entries if at capacity
            if len(self._store) >= self._max_size:
                oldest_key = min(self._store, key=lambda k: self._store[k]["expires_at"])
                del self._store[oldest_key]
            self._store[cache_key] = {
                "value": value,
                "expires_at": time.time() + ttl
            }

    async def delete(self, key: str):
        cache_key = self._make_key(key)
        if self._backend == "redis":
            try:
                await self._redis.delete(cache_key)
            except Exception:
                pass
        else:
            self._store.pop(cache_key, None)

    async def get_stats(self) -> dict:
        if self._backend == "redis":
            try:
                info = await self._redis.info("memory")
                keys = await self._redis.dbsize()
                return {"backend": "redis", "keys": keys, "memory_mb": info.get("used_memory_human")}
            except Exception:
                return {"backend": "redis", "error": "could not connect"}
        else:
            now = time.time()
            active = sum(1 for v in self._store.values() if v["expires_at"] > now)
            return {"backend": "memory", "total_keys": len(self._store), "active_keys": active}

    def _make_key(self, target: str) -> str:
        import hashlib
        h = hashlib.md5(target.encode()).hexdigest()
        return f"threat:{h}"
