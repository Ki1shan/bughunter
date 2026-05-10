"""
BugHunter AI Elite - Execution Controller
Centralized HTTP request execution, throttling, rate limiting, and governance layer.
"""

import asyncio
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from urllib.parse import urlparse
import httpx

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    BB_MODE = "bb_mode"
    AGGRESSIVE = "aggressive"
    LAB_MODE = "lab_mode"


class RequestPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


class RiskLevel(Enum):
    SAFE = "safe"
    MEDIUM = "medium"
    HIGH = "high"
    DANGEROUS = "dangerous"


@dataclass
class RequestMetadata:
    request_id: str = ""
    module: str = ""
    payload_id: str = ""
    param: str = ""
    vuln_type: str = ""
    mode: str = "bb_mode"
    risk_level: str = "safe"
    priority: int = 2
    timestamp: str = ""
    target_url: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "module": self.module,
            "payload_id": self.payload_id,
            "param": self.param,
            "vuln_type": self.vuln_type,
            "mode": self.mode,
            "risk_level": self.risk_level,
            "priority": self.priority,
            "timestamp": self.timestamp,
            "target_url": self.target_url,
        }


@dataclass
class ExecutionResponse:
    status_code: int = 0
    response_time: float = 0.0
    headers: Dict = field(default_factory=dict)
    body: str = ""
    error: Optional[str] = None
    request_metadata: RequestMetadata = field(default_factory=RequestMetadata)
    redirect_url: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "status_code": self.status_code,
            "response_time": self.response_time,
            "headers": self.headers,
            "body": self.body[:1000] if self.body else "",
            "error": self.error,
            "request_metadata": self.request_metadata.to_dict(),
            "redirect_url": self.redirect_url,
        }
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300 and not self.error
    
    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600
    
    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500


@dataclass
class RetryPolicy:
    max_retries: int = 3
    base_delay: float = 0.5
    max_delay: float = 5.0
    exponential_backoff: bool = True
    retry_on: List[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])


@dataclass
class RateLimitConfig:
    requests_per_second: float = 10.0
    requests_per_minute: float = 100.0
    concurrent_requests: int = 10
    per_host_limits: Dict[str, Dict[str, float]] = field(default_factory=dict)
    enabled: bool = True


class TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_update = time.time()
    
    def consume(self, tokens: float = 1.0) -> bool:
        now = time.time()
        elapsed = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_update = now
        
        if self.tokens >= tokens:
            self.tokens -= tokens
            return True
        return False
    
    def wait_time(self, tokens: float = 1.0) -> float:
        if self.tokens >= tokens:
            return 0.0
        return (tokens - self.tokens) / self.rate


class ExecutionController:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._session: Optional[httpx.AsyncClient] = None
        
        self.user_agent = self.config.get("user_agent", "BugHunter-AI/v2.0")
        self.timeout = self.config.get("request_timeout", 10)
        
        self.rate_limit = self._load_rate_limit_config()
        self.retry_policy = self._load_retry_policy()
        
        self._global_bucket = TokenBucket(
            self.rate_limit.requests_per_second,
            self.rate_limit.requests_per_second * 2
        )
        self._host_buckets: Dict[str, TokenBucket] = {}
        
        self._semaphore = asyncio.Semaphore(self.rate_limit.concurrent_requests)
        
        self._request_count = 0
        self._start_time = time.time()
        
        self._execution_mode = ExecutionMode.BB_MODE
        self._risk_level = RiskLevel.SAFE
        
        self._request_log: List[Dict] = []
        self._max_log_size = 10000
        
        self._blocked_hosts: Set[str] = set()
        self._blocked_patterns: List[str] = []
    
    def _load_rate_limit_config(self) -> RateLimitConfig:
        return RateLimitConfig(
            requests_per_second=self.config.get("rate_limit_rps", 10.0),
            requests_per_minute=self.config.get("rate_limit_rpm", 100.0),
            concurrent_requests=self.config.get("max_concurrent_requests", 10),
            per_host_limits={},
            enabled=self.config.get("rate_limiting_enabled", True)
        )
    
    def _load_retry_policy(self) -> RetryPolicy:
        return RetryPolicy(
            max_retries=self.config.get("max_retries", 3),
            base_delay=self.config.get("retry_base_delay", 0.5),
            max_delay=self.config.get("retry_max_delay", 5.0),
            exponential_backoff=self.config.get("exponential_backoff", True)
        )
    
    async def _get_session(self) -> httpx.AsyncClient:
        if self._session is None or self._session.is_closed:
            self._session = httpx.AsyncClient(
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent},
                follow_redirects=False,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)
            )
        return self._session
    
    async def close(self):
        if self._session and not self._session.is_closed:
            await self._session.aclose()
            self._session = None
    
    def _get_host_bucket(self, url: str) -> TokenBucket:
        parsed = urlparse(url)
        host = parsed.netloc
        
        if host not in self._host_buckets:
            host_config = self.rate_limit.per_host_limits.get(host, {})
            rate = host_config.get("rps", self.rate_limit.requests_per_second)
            self._host_buckets[host] = TokenBucket(rate, rate * 2)
        
        return self._host_buckets[host]
    
    async def _acquire_throttle(self, url: str, priority: int = 2):
        if not self.rate_limit.enabled:
            return
        
        await self._semaphore.acquire()
        
        global_delay = self._global_bucket.wait_time()
        host_bucket = self._get_host_bucket(url)
        host_delay = host_bucket.wait_time()
        
        max_delay = max(global_delay, host_delay)
        
        if priority < RequestPriority.HIGH.value:
            await asyncio.sleep(max_delay)
    
    def _release_throttle(self, url: str):
        self._semaphore.release()
        
        if self.rate_limit.enabled:
            self._global_bucket.consume()
            host_bucket = self._get_host_bucket(url)
            host_bucket.consume()
    
    def _generate_request_id(self) -> str:
        self._request_count += 1
        return f"REQ-{self._request_count:06d}"
    
    async def _execute_with_retry(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        allow_redirects: bool = False,
        metadata: Optional[RequestMetadata] = None,
    ) -> ExecutionResponse:
        
        session = await self._get_session()
        last_error = None
        last_response = None
        
        for attempt in range(self.retry_policy.max_retries + 1):
            try:
                start_time = time.time()
                
                if method.upper() == "GET":
                    response = await session.get(url, params=params, headers=headers, allow_redirects=allow_redirects)
                elif method.upper() == "POST":
                    response = await session.post(url, params=params, json=json, data=data, headers=headers, allow_redirects=allow_redirects)
                elif method.upper() == "PUT":
                    response = await session.put(url, params=params, json=json, data=data, headers=headers, allow_redirects=allow_redirects)
                elif method.upper() == "DELETE":
                    response = await session.delete(url, params=params, headers=headers, allow_redirects=allow_redirects)
                elif method.upper() == "HEAD":
                    response = await session.head(url, params=params, headers=headers, allow_redirects=allow_redirects)
                else:
                    response = await session.request(method, url, params=params, json=json, data=data, headers=headers, allow_redirects=allow_redirects)
                
                response_time = time.time() - start_time
                
                exec_response = ExecutionResponse(
                    status_code=response.status_code,
                    response_time=response_time,
                    headers=dict(response.headers),
                    body=response.text,
                    request_metadata=metadata or RequestMetadata(),
                    redirect_url=str(response.url) if response.is_redirect else None
                )
                
                if attempt > 0:
                    logger.info(f"Request succeeded on attempt {attempt + 1}: {metadata.request_id if metadata else 'unknown'}")
                
                return exec_response
                
            except httpx.TimeoutException as e:
                last_error = f"Timeout: {str(e)}"
                last_response = ExecutionResponse(
                    status_code=0,
                    error=last_error,
                    request_metadata=metadata or RequestMetadata()
                )
                
            except httpx.ConnectError as e:
                last_error = f"Connection error: {str(e)}"
                last_response = ExecutionResponse(
                    status_code=0,
                    error=last_error,
                    request_metadata=metadata or RequestMetadata()
                )
                
            except Exception as e:
                last_error = f"Request failed: {str(e)}"
                last_response = ExecutionResponse(
                    status_code=0,
                    error=last_error,
                    request_metadata=metadata or RequestMetadata()
                )
            
            if attempt < self.retry_policy.max_retries:
                if last_response.status_code in self.retry_policy.retry_on:
                    if self.retry_policy.exponential_backoff:
                        delay = min(
                            self.retry_policy.base_delay * (2 ** attempt),
                            self.retry_policy.max_delay
                        )
                    else:
                        delay = self.retry_policy.base_delay
                    
                    logger.debug(f"Retrying after {delay}s (attempt {attempt + 1})")
                    await asyncio.sleep(delay)
                else:
                    break
        
        return last_response or ExecutionResponse(error=last_error or "Unknown error")
    
    async def execute(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        allow_redirects: bool = False,
        metadata: Optional[Dict] = None,
    ) -> ExecutionResponse:
        
        parsed = urlparse(url)
        host = parsed.netloc
        
        if host in self._blocked_hosts:
            return ExecutionResponse(
                error="Host blocked",
                request_metadata=RequestMetadata(target_url=url)
            )
        
        request_metadata = RequestMetadata(
            request_id=self._generate_request_id(),
            module=metadata.get("module", "") if metadata else "",
            payload_id=metadata.get("payload_id", "") if metadata else "",
            param=metadata.get("param", "") if metadata else "",
            vuln_type=metadata.get("vuln_type", "") if metadata else "",
            mode=self._execution_mode.value,
            risk_level=self._risk_level.value,
            target_url=url,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
        )
        
        priority = metadata.get("priority", 2) if metadata else 2
        
        try:
            await self._acquire_throttle(url, priority)
            
            result = await self._execute_with_retry(
                method=method,
                url=url,
                headers=headers,
                params=params,
                data=data,
                json=json,
                allow_redirects=allow_redirects,
                metadata=request_metadata
            )
            
            self._log_request(result)
            
            return result
            
        finally:
            self._release_throttle(url)
    
    async def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        allow_redirects: bool = False,
        metadata: Optional[Dict] = None,
    ) -> ExecutionResponse:
        return await self.execute("GET", url, headers=headers, params=params, allow_redirects=allow_redirects, metadata=metadata)
    
    async def post(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        allow_redirects: bool = False,
        metadata: Optional[Dict] = None,
    ) -> ExecutionResponse:
        return await self.execute("POST", url, headers=headers, data=data, json=json, allow_redirects=allow_redirects, metadata=metadata)
    
    async def put(
        self,
        url: str,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ) -> ExecutionResponse:
        return await self.execute("PUT", url, headers=headers, data=data, json=json, allow_redirects=False, metadata=metadata)
    
    async def delete(
        self,
        url: str,
        headers: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ) -> ExecutionResponse:
        return await self.execute("DELETE", url, headers=headers, allow_redirects=False, metadata=metadata)
    
    async def head(
        self,
        url: str,
        headers: Optional[Dict] = None,
        metadata: Optional[Dict] = None,
    ) -> ExecutionResponse:
        return await self.execute("HEAD", url, headers=headers, allow_redirects=False, metadata=metadata)
    
    def _log_request(self, response: ExecutionResponse):
        self._request_log.append(response.to_dict())
        
        if len(self._request_log) > self._max_log_size:
            self._request_log = self._request_log[-self._max_log_size:]
    
    def get_execution_stats(self) -> Dict:
        elapsed = time.time() - self._start_time
        return {
            "total_requests": self._request_count,
            "elapsed_time": elapsed,
            "requests_per_second": self._request_count / elapsed if elapsed > 0 else 0,
            "current_mode": self._execution_mode.value,
            "risk_level": self._risk_level.value,
            "rate_limiting_enabled": self.rate_limit.enabled,
            "concurrent_limit": self.rate_limit.concurrent_requests,
        }
    
    def set_execution_mode(self, mode: ExecutionMode):
        self._execution_mode = mode
        logger.info(f"Execution mode set to: {mode.value}")
    
    def set_risk_level(self, level: RiskLevel):
        self._risk_level = level
        logger.info(f"Risk level set to: {level.value}")
    
    def block_host(self, host: str):
        self._blocked_hosts.add(host)
        logger.info(f"Host blocked: {host}")
    
    def unblock_host(self, host: str):
        self._blocked_hosts.discard(host)
        logger.info(f"Host unblocked: {host}")
    
    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        return self._request_log[-limit:]
    
    def update_config(self, config: Dict):
        self.config.update(config)
        
        if "rate_limit_rps" in config or "max_concurrent_requests" in config:
            self.rate_limit = self._load_rate_limit_config()
            self._global_bucket = TokenBucket(
                self.rate_limit.requests_per_second,
                self.rate_limit.requests_per_second * 2
            )
            self._semaphore = asyncio.Semaphore(self.rate_limit.concurrent_requests)
        
        if "max_retries" in config:
            self.retry_policy = self._load_retry_policy()


_controller_instance: Optional[ExecutionController] = None


def get_execution_controller(config: Optional[Dict] = None) -> ExecutionController:
    global _controller_instance
    
    if _controller_instance is None:
        _controller_instance = ExecutionController(config)
    
    return _controller_instance


def reset_execution_controller():
    global _controller_instance
    
    if _controller_instance:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_controller_instance.close())
            else:
                loop.run_until_complete(_controller_instance.close())
        except Exception:
            pass
    
    _controller_instance = None


async def execute_request(
    method: str,
    url: str,
    config: Optional[Dict] = None,
    **kwargs
) -> ExecutionResponse:
    controller = get_execution_controller(config)
    return await controller.execute(method, url, **kwargs)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    config = {
        "rate_limit_rps": 5.0,
        "max_concurrent_requests": 5,
        "max_retries": 2,
    }
    
    controller = get_execution_controller(config)
    
    print("\n=== Execution Controller Test ===\n")
    
    async def test():
        response = await controller.get("https://httpbin.org/get")
        print(f"Status: {response.status_code}")
        print(f"Time: {response.response_time:.2f}s")
        print(f"Success: {response.is_success}")
        
        stats = controller.get_execution_stats()
        print(f"\nStats: {stats}")
        
        await controller.close()
    
    asyncio.run(test())