import asyncio
import heapq
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Callable
from enum import Enum
from modules.logging_config import logger


class Priority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    BACKGROUND = 5


@dataclass(order=True)
class Task:
    priority: int
    endpoint: str = field(compare=False)
    method: str = field(compare=False)
    params: List[str] = field(compare=False)
    task_type: str = field(compare=False)
    score: float = field(compare=False)
    depth: int = field(compare=False)
    reassess_count: int = field(default=0, compare=False)
    created_at: float = field(default_factory=time.time, compare=False)
    metadata: Dict = field(default_factory=dict, compare=False)


class IntelligentScheduler:
    def __init__(self, max_concurrent=10, max_reassess=2):
        self.queue = []
        self.completed = set()
        self.failed = {}
        self.in_progress = {}
        self.max_concurrent = max_concurrent
        self.max_reassess = max_reassess
        self.results_cache = {}
        self.priority_weights = {
            "ai_analysis": 0.8,
            "mutation": 0.9,
            "logic": 1.0,
            "heuristic": 1.1,
            "behavior": 1.2,
            "auth_simulation": 0.7
        }
        self._lock = asyncio.Lock()
    
    def _calculate_priority(self, task: Task) -> int:
        base_priority = task.priority
        
        type_weight = self.priority_weights.get(task.task_type, 1.0)
        
        score_bonus = 0
        if task.score >= 8:
            score_bonus = -2
        elif task.score >= 5:
            score_bonus = -1
        
        depth_penalty = task.depth * 0.1
        
        final_priority = int((base_priority * type_weight) + depth_penalty + score_bonus)
        
        final_priority = max(1, min(final_priority, 5))
        
        return final_priority
    
    async def add_task(self, endpoint: str, method: str, params: List[str], 
                      task_type: str, score: float = 0, depth: int = 0,
                      priority: Priority = Priority.MEDIUM, metadata: Dict = None):
        task = Task(
            priority=priority.value,
            endpoint=endpoint,
            method=method,
            params=params,
            task_type=task_type,
            score=score,
            depth=depth,
            metadata=metadata or {}
        )
        
        calculated_priority = self._calculate_priority(task)
        task.priority = calculated_priority
        
        async with self._lock:
            heapq.heappush(self.queue, task)
            logger.debug(f"Added task: {endpoint} (priority: {calculated_priority})")
    
    async def add_batch(self, tasks: List[Dict]):
        for task_data in tasks:
            await self.add_task(**task_data)
        logger.info(f"Batch added: {len(tasks)} tasks")
    
    async def get_next_task(self):
        async with self._lock:
            while self.queue:
                task = heapq.heappop(self.queue)
                
                task_key = f"{task.endpoint}:{task.task_type}"
                if task_key in self.completed:
                    continue
                    
                if task_key in self.failed and task.reassess_count >= self.max_reassess:
                    continue
                
                self.in_progress[task_key] = task
                return task
            return None
    
    async def mark_completed(self, task: Task, result: Any = None):
        task_key = f"{task.endpoint}:{task.task_type}"
        
        async with self._lock:
            if task_key in self.in_progress:
                del self.in_progress[task_key]
            self.completed.add(task_key)
            
            if result:
                self.results_cache[task.endpoint] = self.results_cache.get(task.endpoint, {})
                self.results_cache[task.endpoint][task.task_type] = result
        
        logger.debug(f"Task completed: {task_key}")
    
    async def mark_failed(self, task: Task, error: str):
        task_key = f"{task.endpoint}:{task.task_type}"
        
        async with self._lock:
            if task_key in self.in_progress:
                del self.in_progress[task_key]
            
            if task_key not in self.failed:
                self.failed[task_key] = {"count": 0, "errors": []}
            
            self.failed[task_key]["count"] += 1
            self.failed[task_key]["errors"].append(error)
            
            if self.failed[task_key]["count"] < self.max_reassess:
                task.reassess_count += 1
                task.priority = min(task.priority + 1, 5)
                heapq.heappush(self.queue, task)
                logger.info(f"Task re-queued: {task_key} (attempt {task.reassess_count})")
    
    async def add_reassessment_tasks(self, endpoint: str, params: List[str]):
        reassessment_tasks = [
            {"endpoint": endpoint, "method": "GET", "params": params, 
             "task_type": "mutation", "score": 7, "depth": 1, 
             "priority": Priority.HIGH},
            {"endpoint": endpoint, "method": "GET", "params": params,
             "task_type": "auth_simulation", "score": 8, "depth": 1,
             "priority": Priority.CRITICAL}
        ]
        
        for task_data in reassessment_tasks:
            await self.add_task(**task_data)
        
        logger.info(f"Reassessment tasks added for {endpoint}")
    
    def get_stats(self):
        return {
            "pending": len(self.queue),
            "in_progress": len(self.in_progress),
            "completed": len(self.completed),
            "failed": len(self.failed),
            "cache_size": len(self.results_cache)
        }
    
    async def wait_for_completion(self, timeout=300):
        start = time.time()
        
        while time.time() - start < timeout:
            async with self._lock:
                if not self.queue and not self.in_progress:
                    return True
            await asyncio.sleep(1)
        
        return False
    
    def get_cached_result(self, endpoint: str, task_type: str = None):
        if task_type:
            return self.results_cache.get(endpoint, {}).get(task_type)
        return self.results_cache.get(endpoint, {})


class ParallelExecutor:
    def __init__(self, max_workers=10, rate_limit=20):
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.semaphore = asyncio.Semaphore(max_workers)
        self.total_requests = 0
        self.request_timestamps = []
    
    async def throttled_execute(self, func: Callable, *args, **kwargs):
        async with self.semaphore:
            current_time = time.time()
            
            self.request_timestamps = [
                ts for ts in self.request_timestamps 
                if current_time - ts < 1.0
            ]
            
            if len(self.request_timestamps) >= self.rate_limit:
                await asyncio.sleep(1.0 - (current_time - self.request_timestamps[0]))
                self.request_timestamps = []
            
            self.request_timestamps.append(time.time())
            self.total_requests += 1
            
            return await func(*args, **kwargs)
    
    async def execute_parallel(self, tasks: List[Callable]):
        results = await asyncio.gather(
            *[self.throttled_execute(task) for task in tasks],
            return_exceptions=True
        )
        return results
    
    async def batch_exploit(self, endpoints: List[Dict], exploit_func: Callable):
        tasks = []
        
        for ep in endpoints:
            task = lambda: exploit_func(ep)
            tasks.append(self.throttled_execute(exploit_func, ep))
        
        return await asyncio.gather(*tasks, return_exceptions=True)


async def run_scheduled_tasks(scheduler: IntelligentScheduler, worker_func: Callable):
    while True:
        task = await scheduler.get_next_task()
        
        if task is None:
            break
        
        try:
            result = await worker_func(task)
            await scheduler.mark_completed(task, result)
            
            if isinstance(result, dict) and result.get("reassess"):
                await scheduler.add_reassessment_tasks(task.endpoint, task.params)
                
        except Exception as e:
            await scheduler.mark_failed(task, str(e))


def create_scheduler(max_concurrent=10):
    return IntelligentScheduler(max_concurrent=max_concurrent)


def create_executor(max_workers=15, rate_limit=30):
    return ParallelExecutor(max_workers=max_workers, rate_limit=rate_limit)