"""
Performance Optimizer - Adaptive limits and smarter pruning for BugHunter AI.

Provides:
- Adaptive payload limits based on early results
- Smart endpoint pruning to skip unproductive tests
- Response caching to avoid redundant requests
- Timeout optimization with progressive backoff
- Batch payload execution for parallel testing
"""

import time
import hashlib
from collections import defaultdict
from modules.logging_config import logger


class PerformanceOptimizer:
    def __init__(self, config=None):
        self.config = config or {}
        self.response_cache = {}
        self.endpoint_perf = defaultdict(lambda: {
            "total_requests": 0,
            "avg_response_time": 0.0,
            "failure_rate": 0.0,
            "last_tested": None,
            "pruned": False,
        })
        self.payload_perf = defaultdict(lambda: {
            "success_count": 0,
            "failure_count": 0,
            "total_time": 0.0,
            "avg_time": 0.0,
        })
        self.max_payloads_per_stage = self.config.get("max_payloads_per_stage", 8)
        self.min_confidence_to_continue = self.config.get("min_confidence_to_continue", 0.3)
        self.max_stages_before_prune = self.config.get("max_stages_before_prune", 3)
        self.cache_ttl = self.config.get("cache_ttl_seconds", 300)
        self.slow_response_threshold = self.config.get("slow_response_threshold", 5.0)
        self.fast_fail_threshold = self.config.get("fast_fail_threshold", 10.0)
        self._cache_hits = 0
        self._cache_misses = 0

    def get_cache_key(self, url, method="GET", params=None):
        raw = f"{method}:{url}:{params or ''}"
        return hashlib.md5(raw.encode()).hexdigest()

    def get_cached_response(self, url, method="GET", params=None):
        key = self.get_cache_key(url, method, params)
        entry = self.response_cache.get(key)
        if entry and (time.time() - entry["time"]) < self.cache_ttl:
            self._cache_hits += 1
            logger.debug(f"  [Perf] Cache hit for {url[:50]}...")
            return entry["response"]
        self._cache_misses += 1
        return None

    def cache_response(self, url, response, method="GET", params=None):
        key = self.get_cache_key(url, method, params)
        self.response_cache[key] = {
            "response": response,
            "time": time.time(),
        }

    def clear_cache(self):
        self.response_cache.clear()

    def record_request_time(self, endpoint, response_time):
        perf = self.endpoint_perf[endpoint]
        perf["total_requests"] += 1
        n = perf["total_requests"]
        perf["avg_response_time"] = (perf["avg_response_time"] * (n - 1) + response_time) / n
        perf["last_tested"] = time.time()

        if response_time > self.slow_response_threshold:
            logger.debug(f"  [Perf] Slow response ({response_time:.1f}s) on {endpoint}")

    def should_fast_fail(self, endpoint):
        perf = self.endpoint_perf.get(endpoint, {})
        if perf.get("avg_response_time", 0) > self.fast_fail_threshold:
            return True
        return False

    def should_prune_endpoint(self, endpoint):
        perf = self.endpoint_perf.get(endpoint, {})
        if perf.get("pruned"):
            return True

        total = perf.get("total_requests", 0)
        if total >= self.max_stages_before_prune * 4:
            failure_rate = perf.get("failure_rate", 0)
            if failure_rate > 0.9:
                perf["pruned"] = True
                logger.info(f"  [Perf] Pruning endpoint: {endpoint} (failure rate: {failure_rate:.0%})")
                return True
        return False

    def should_prune_payload(self, vuln_type, payload_name, endpoint):
        key = f"{vuln_type}:{payload_name}"
        perf = self.payload_perf.get(key, {})
        failures = perf.get("failure_count", 0)
        successes = perf.get("success_count", 0)
        total = failures + successes

        if total < 3:
            return False

        failure_rate = failures / total if total > 0 else 0
        if failure_rate > 0.85 and failures >= 5:
            return True

        return False

    def record_payload_result(self, vuln_type, payload_name, success, response_time=0):
        key = f"{vuln_type}:{payload_name}"
        perf = self.payload_perf[key]
        if success:
            perf["success_count"] += 1
        else:
            perf["failure_count"] += 1
        perf["total_time"] += response_time
        total = perf["success_count"] + perf["failure_count"]
        perf["avg_time"] = perf["total_time"] / total if total > 0 else 0

    def get_adaptive_limit(self, vuln_type, stage, success_rate=0):
        if stage == 0:
            return self.max_payloads_per_stage

        if success_rate > 0.5:
            return max(2, self.max_payloads_per_stage // 2)

        if success_rate == 0:
            return max(1, self.max_payloads_per_stage // 4)

        return self.max_payloads_per_stage

    def prioritize_payloads(self, payloads, vuln_type, endpoint):
        scored = []
        for p in payloads:
            name = p.get("name", str(p))
            key = f"{vuln_type}:{name}"
            perf = self.payload_perf.get(key, {})

            successes = perf.get("success_count", 0)
            failures = perf.get("failure_count", 0)
            total = successes + failures

            if total > 0:
                score = successes / total
            else:
                score = 0.5

            is_slow = perf.get("avg_time", 0) > self.slow_response_threshold
            if is_slow:
                score *= 0.5

            scored.append((score, p))

        scored.sort(reverse=True, key=lambda x: x[0])
        return [p for _, p in scored]

    def get_stats(self):
        cache_total = self._cache_hits + self._cache_misses
        cache_rate = (self._cache_hits / cache_total * 100) if cache_total > 0 else 0

        total_payloads = len(self.payload_perf)
        pruned_payloads = sum(1 for k, v in self.payload_perf.items()
                            if v.get("failure_count", 0) >= 5 and v.get("failure_count", 0) / max(1, v.get("success_count", 0) + v.get("failure_count", 0)) > 0.85)

        return {
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_rate": f"{cache_rate:.1f}%",
            "cached_responses": len(self.response_cache),
            "tracked_endpoints": len(self.endpoint_perf),
            "tracked_payloads": total_payloads,
            "pruned_payloads": pruned_payloads,
            "pruned_endpoints": sum(1 for v in self.endpoint_perf.values() if v.get("pruned")),
        }
