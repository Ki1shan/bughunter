"""
BugHunter AI Elite - Resilience Manager
Operational hardening, fault tolerance, and stress testing infrastructure.
"""

import asyncio
import gc
import logging
import time
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from enum import Enum

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger(__name__)


class ResilienceStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    FAILURE = "failure"


class StressTestType(Enum):
    TIMEOUT_STORM = "timeout_storm"
    CONCURRENCY_SATURATION = "concurrency_saturation"
    RETRY_FLOOD = "retry_flood"
    LARGE_RESPONSE = "large_response"
    WAF_THROTTLING = "waf_throttling"
    CONNECTION_RESET = "connection_reset"
    MALFORMED_RESPONSE = "malformed_response"
    MEMORY_PRESSURE = "memory_pressure"
    EVENT_LOOP_BLOCK = "event_loop_block"


@dataclass
class ResilienceMetrics:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    retried_requests: int = 0
    timeouts: int = 0
    connection_errors: int = 0
    rate_limited: int = 0
    throttled_events: int = 0
    circuit_breaker_trips: int = 0
    peak_concurrent: int = 0
    avg_response_time: float = 0.0
    max_response_time: float = 0.0
    total_retries: int = 0
    retry_success_rate: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "retried_requests": self.retried_requests,
            "timeouts": self.timeouts,
            "connection_errors": self.connection_errors,
            "rate_limited": self.rate_limited,
            "throttled_events": self.throttled_events,
            "circuit_breaker_trips": self.circuit_breaker_trips,
            "peak_concurrent": self.peak_concurrent,
            "avg_response_time": round(self.avg_response_time, 3),
            "max_response_time": round(self.max_response_time, 3),
            "total_retries": self.total_retries,
            "retry_success_rate": round(self.retry_success_rate, 2),
        }


@dataclass
class ResilienceConfig:
    max_retries: int = 5
    retry_ceiling: int = 10
    circuit_breaker_threshold: int = 20
    circuit_breaker_timeout: float = 30.0
    timeout_detection_threshold: float = 0.3
    memory_pressure_threshold: float = 0.85
    concurrency_saturation_threshold: float = 0.90
    response_size_limit: int = 10 * 1024 * 1024
    adaptive_backoff: bool = True
    emergency_concurrency_reduction: float = 0.5
    
    def to_dict(self) -> Dict:
        return {
            "max_retries": self.max_retries,
            "retry_ceiling": self.retry_ceiling,
            "circuit_breaker_threshold": self.circuit_breaker_threshold,
            "circuit_breaker_timeout": self.circuit_breaker_timeout,
            "timeout_detection_threshold": self.timeout_detection_threshold,
            "memory_pressure_threshold": self.memory_pressure_threshold,
            "concurrency_saturation_threshold": self.concurrency_saturation_threshold,
            "response_size_limit": self.response_size_limit,
            "adaptive_backoff": self.adaptive_backoff,
            "emergency_concurrency_reduction": self.emergency_concurrency_reduction,
        }


class CircuitBreaker:
    def __init__(self, threshold: int = 20, timeout: float = 30.0):
        self.threshold = threshold
        self.timeout = timeout
        self.failures = 0
        self.last_failure_time: Optional[float] = None
        self.is_open = False
    
    def record_failure(self):
        self.failures += 1
        self.last_failure_time = time.time()
        
        if self.failures >= self.threshold:
            self.is_open = True
    
    def record_success(self):
        self.failures = max(0, self.failures - 1)
        if self.failures < self.threshold:
            self.is_open = False
    
    def can_proceed(self) -> bool:
        if not self.is_open:
            return True
        
        if self.last_failure_time:
            if time.time() - self.last_failure_time > self.timeout:
                self.is_open = False
                self.failures = 0
                return True
        
        return False


class ResilienceManager:
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, config: Optional[Dict] = None):
        if hasattr(self, '_initialized') and self._initialized:
            return
        
        self.config = config or {}
        self._initialized = True
        
        self.metrics = ResilienceMetrics()
        self.resilience_config = ResilienceConfig(**self.config)
        
        self._circuit_breaker = CircuitBreaker(
            threshold=self.resilience_config.circuit_breaker_threshold,
            timeout=self.resilience_config.circuit_breaker_timeout
        )
        
        self._start_time = time.time()
        self._stress_test_active = False
        self._stress_tests_passed = 0
        self._stress_tests_failed = 0
        
        self._response_times: List[float] = []
        self._max_response_history = 1000
        
        self._concurrency_peak = 0
        self._current_concurrent = 0
        
        self._event_loop_monitor_active = False
    
    def record_request_start(self):
        self.metrics.total_requests += 1
        self._current_concurrent += 1
        self._concurrency_peak = max(self._concurrency_peak, self._current_concurrent)
        self.metrics.peak_concurrent = self._concurrency_peak
    
    def record_request_end(self, response_time: float, success: bool = True):
        self._current_concurrent = max(0, self._current_concurrent - 1)
        
        self._response_times.append(response_time)
        if len(self._response_times) > self._max_response_history:
            self._response_times = self._response_times[-self._max_response_history:]
        
        self.metrics.avg_response_time = sum(self._response_times) / len(self._response_times)
        self.metrics.max_response_time = max(self.metrics.max_response_time, response_time)
        
        if success:
            self.metrics.successful_requests += 1
            self._circuit_breaker.record_success()
        else:
            self.metrics.failed_requests += 1
            self._circuit_breaker.record_failure()
            self._circuit_breaker.record_failure()
    
    def record_timeout(self):
        self.metrics.timeouts += 1
        self.metrics.failed_requests += 1
        self._circuit_breaker.record_failure()
    
    def record_connection_error(self):
        self.metrics.connection_errors += 1
        self.metrics.failed_requests += 1
        self._circuit_breaker.record_failure()
    
    def record_rate_limit(self):
        self.metrics.rate_limited += 1
    
    def record_throttle_event(self):
        self.metrics.throttled_events += 1
    
    def record_retry(self, succeeded: bool = False):
        self.metrics.retried_requests += 1
        self.metrics.total_retries += 1
        
        if succeeded:
            if self.metrics.retried_requests > 0:
                success_count = self.metrics.successful_requests
                retry_count = self.metrics.total_retries
                self.metrics.retry_success_rate = (success_count / retry_count) * 100 if retry_count > 0 else 0
    
    def can_proceed(self) -> bool:
        if self._circuit_breaker.is_open:
            if not self._circuit_breaker.can_proceed():
                return False
            else:
                if self._circuit_breaker.failures > 0:
                    self._circuit_breaker.failures -= 1
        
        return True
    
    def get_status(self) -> ResilienceStatus:
        if self.metrics.failed_requests > self.metrics.total_requests * 0.5:
            return ResilienceStatus.FAILURE
        
        if self.metrics.failed_requests > self.metrics.total_requests * 0.3:
            return ResilienceStatus.CRITICAL
        
        if self.metrics.timeouts > self.metrics.total_requests * 0.3:
            return ResilienceStatus.CRITICAL
        
        if self._circuit_breaker.is_open:
            return ResilienceStatus.DEGRADED
        
        return ResilienceStatus.HEALTHY
    
    def get_memory_pressure(self) -> float:
        if not HAS_PSUTIL:
            return 0.0
        
        try:
            process = psutil.Process()
            return process.memory_percent()
        except Exception:
            return 0.0
    
    def is_memory_pressure(self) -> bool:
        pressure = self.get_memory_pressure()
        return pressure > (self.resilience_config.memory_pressure_threshold * 100)
    
    def get_concurrency_saturation(self) -> float:
        max_concurrent = self.resilience_config.max_retries * 2
        return self._concurrency_peak / max_concurrent if max_concurrent > 0 else 0
    
    def detect_event_loop_blocking(self) -> bool:
        try:
            loop = asyncio.get_event_loop()
            if hasattr(loop, 'slow_callback_duration'):
                return loop.slow_callback_duration > 0.1
        except Exception:
            pass
        return False
    
    def get_metrics_summary(self) -> Dict:
        status = self.get_status()
        
        return {
            "status": status.value,
            "metrics": self.metrics.to_dict(),
            "circuit_breaker": {
                "open": self._circuit_breaker.is_open,
                "failures": self._circuit_breaker.failures,
                "threshold": self._circuit_breaker.threshold,
            },
            "memory_pressure": round(self.get_memory_pressure(), 2),
            "concurrency_saturation": round(self.get_concurrency_saturation(), 2),
            "uptime_seconds": round(time.time() - self._start_time, 2),
        }
    
    def adapt_to_pressure(self) -> Dict:
        adaptations = []
        
        if self.is_memory_pressure():
            adaptations.append({
                "action": "reduce_concurrency",
                "reduction": self.resilience_config.emergency_concurrency_reduction,
                "reason": "memory_pressure"
            })
        
        if self._circuit_breaker.is_open:
            adaptations.append({
                "action": "enable_circuit_breaker",
                "reason": "high_failure_rate"
            })
        
        timeout_rate = self.metrics.timeouts / self.metrics.total_requests if self.metrics.total_requests > 0 else 0
        if timeout_rate > self.resilience_config.timeout_detection_threshold:
            adaptations.append({
                "action": "increase_timeout",
                "factor": 1.5,
                "reason": "high_timeout_rate"
            })
        
        return adaptations
    
    async def simulate_timeout_storm(self, duration: float = 10.0):
        self._stress_test_active = True
        test_start = time.time()
        successes = 0
        failures = 0
        
        logger.info("[Stress Test] Starting timeout storm simulation")
        
        while time.time() - test_start < duration:
            if random.random() < 0.8:
                self.record_timeout()
                failures += 1
            else:
                self.record_request_end(random.uniform(0.1, 0.5), True)
                successes += 1
            
            await asyncio.sleep(0.1)
        
        self._stress_test_active = False
        
        if failures > successes:
            self._stress_tests_failed += 1
        else:
            self._stress_tests_passed += 1
        
        return {"successes": successes, "failures": failures}
    
    async def simulate_waf_throttling(self, duration: float = 10.0):
        self._stress_test_active = True
        test_start = time.time()
        throttled_count = 0
        normal_count = 0
        
        logger.info("[Stress Test] Starting WAF throttling simulation")
        
        while time.time() - test_start < duration:
            if random.random() < 0.3:
                self.record_throttle_event()
                self.record_rate_limit()
                throttled_count += 1
            else:
                self.record_request_end(random.uniform(0.1, 0.3), True)
                normal_count += 1
            
            await asyncio.sleep(0.1)
        
        self._stress_test_active = False
        
        if throttled_count > normal_count * 0.5:
            self._stress_tests_failed += 1
        else:
            self._stress_tests_passed += 1
        
        return {"throttled": throttled_count, "normal": normal_count}
    
    async def simulate_large_response_attack(self, response_size_mb: float = 5.0):
        logger.info(f"[Stress Test] Starting large response simulation ({response_size_mb}MB)")
        
        responses_processed = 0
        oversized = 0
        
        for _ in range(10):
            test_size = random.uniform(0.1, response_size_mb * 1024 * 1024)
            
            if test_size > self.resilience_config.response_size_limit:
                oversized += 1
                self.record_request_end(5.0, False)
            else:
                self.record_request_end(0.5, True)
                responses_processed += 1
        
        return {"processed": responses_processed, "oversized": oversized}
    
    async def simulate_concurrency_saturation(self, max_concurrent: int = 50):
        logger.info(f"[Stress Test] Starting concurrency saturation ({max_concurrent})")
        
        concurrent_tasks = 0
        completed = 0
        timed_out = 0
        
        async def worker():
            nonlocal concurrent_tasks, completed, timed_out
            concurrent_tasks += 1
            self.record_request_start()
            
            wait_time = random.uniform(0.1, 1.0)
            
            try:
                await asyncio.wait_for(asyncio.sleep(wait_time), timeout=5.0)
                self.record_request_end(wait_time, True)
                completed += 1
            except asyncio.TimeoutError:
                self.record_timeout()
                timed_out += 1
            
            concurrent_tasks -= 1
        
        tasks = [asyncio.create_task(worker()) for _ in range(max_concurrent)]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return {"completed": completed, "timed_out": timed_out}
    
    async def run_all_stress_tests(self):
        results = {}
        
        logger.info("[Stress Test] Running resilience stress tests")
        
        try:
            results["timeout_storm"] = await self.simulate_timeout_storm(5.0)
        except Exception as e:
            results["timeout_storm"] = {"error": str(e)}
        
        try:
            results["waf_throttling"] = await self.simulate_waf_throttling(5.0)
        except Exception as e:
            results["waf_throttling"] = {"error": str(e)}
        
        try:
            results["concurrency_saturation"] = await self.simulate_concurrency_saturation(20)
        except Exception as e:
            results["concurrency_saturation"] = {"error": str(e)}
        
        try:
            results["large_response"] = await self.simulate_large_response_attack(10.0)
        except Exception as e:
            results["large_response"] = {"error": str(e)}
        
        return results
    
    def get_stress_test_results(self) -> Dict:
        return {
            "tests_passed": self._stress_tests_passed,
            "tests_failed": self._stress_tests_failed,
            "active": self._stress_test_active
        }
    
    def reset_metrics(self):
        self.metrics = ResilienceMetrics()
        self._response_times = []
        self._concurrency_peak = 0
        self._current_concurrent = 0
        self._start_time = time.time()
        self._circuit_breaker = CircuitBreaker(
            threshold=self.resilience_config.circuit_breaker_threshold,
            timeout=self.resilience_config.circuit_breaker_timeout
        )
    
    def update_config(self, updates: Dict):
        for key, value in updates.items():
            if hasattr(self.resilience_config, key):
                setattr(self.resilience_config, key, value)
                
                if key == "circuit_breaker_threshold":
                    self._circuit_breaker.threshold = value
                elif key == "circuit_breaker_timeout":
                    self._circuit_breaker.timeout = value


_resilience_instance: Optional[ResilienceManager] = None


def get_resilience_manager(config: Optional[Dict] = None) -> ResilienceManager:
    global _resilience_instance
    
    if _resilience_instance is None:
        _resilience_instance = ResilienceManager(config)
    
    return _resilience_instance


def reset_resilience_manager():
    global _resilience_instance
    _resilience_instance = None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("\n=== Resilience Manager Test ===\n")
    
    manager = get_resilience_manager()
    
    print("=== Initial Status ===")
    status = manager.get_status()
    print(f"Status: {status.value}")
    
    print("\n=== Simulating Requests ===")
    for i in range(20):
        manager.record_request_start()
        response_time = random.uniform(0.05, 0.5)
        success = random.random() > 0.2
        manager.record_request_end(response_time, success)
        
        if random.random() < 0.1:
            manager.record_retry(success=random.random() > 0.5)
    
    print("\n=== Stress Test Simulations ===")
    
    async def run_tests():
        print("\nTimeout storm test:")
        result = await manager.simulate_timeout_storm(2.0)
        print(f"  Result: {result}")
        
        print("\nWAF throttling test:")
        result = await manager.simulate_waf_throttling(2.0)
        print(f"  Result: {result}")
    
    asyncio.run(run_tests())
    
    print("\n=== Final Metrics ===")
    summary = manager.get_metrics_summary()
    print(f"Status: {summary['status']}")
    print(f"Total requests: {summary['metrics']['total_requests']}")
    print(f"Successful: {summary['metrics']['successful_requests']}")
    print(f"Failed: {summary['metrics']['failed_requests']}")
    print(f"Timeouts: {summary['metrics']['timeouts']}")
    print(f"Retries: {summary['metrics']['total_retries']}")
    print(f"Peak concurrent: {summary['metrics']['peak_concurrent']}")
    print(f"Circuit breaker open: {summary['circuit_breaker']['open']}")