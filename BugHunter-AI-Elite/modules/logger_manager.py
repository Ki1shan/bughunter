"""
BugHunter AI Elite - Logger Manager
Professional-grade observability, tracing, and structured logging system.
"""

import asyncio
import json
import logging
import time
import uuid
import os
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from pathlib import Path
import threading


class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventType(Enum):
    SCAN_START = "scan_start"
    SCAN_END = "scan_end"
    MODULE_DISPATCH = "module_dispatch"
    MODULE_COMPLETE = "module_complete"
    PAYLOAD_EXECUTED = "payload_executed"
    PAYLOAD_SKIPPED = "payload_skipped"
    PAYLOAD_FAILED = "payload_failed"
    REQUEST_START = "request_start"
    REQUEST_END = "request_end"
    REQUEST_RETRY = "request_retry"
    REQUEST_THROTTLED = "request_throttled"
    VALIDATOR_DECISION = "validator_decision"
    ESCALATION_ATTEMPT = "escalation_attempt"
    ORCHESTRATION_TRANSITION = "orchestration_transition"
    ERROR = "error"
    EXCEPTION = "exception"
    MODE_CHANGE = "mode_change"
    CONFIG_CHANGE = "config_change"


@dataclass
class TraceContext:
    scan_id: str = ""
    request_id: str = ""
    payload_id: str = ""
    module: str = ""
    vuln_type: str = ""
    correlation_id: str = ""
    parent_trace: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "request_id": self.request_id,
            "payload_id": self.payload_id,
            "module": self.module,
            "vuln_type": self.vuln_type,
            "correlation_id": self.correlation_id,
            "parent_trace": self.parent_trace,
        }


@dataclass
class LogEvent:
    timestamp: str
    level: str
    event_type: str
    message: str
    context: Dict = field(default_factory=dict)
    trace: TraceContext = field(default_factory=TraceContext)
    duration_ms: float = 0.0
    status: str = "success"
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "level": self.level,
            "event_type": self.event_type,
            "message": self.message,
            "context": self.context,
            "trace": self.trace.to_dict(),
            "duration_ms": self.duration_ms,
            "status": self.status,
            "error": self.error,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class PerformanceMetric:
    name: str
    value: float
    unit: str = "ms"
    timestamp: str = ""
    context: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp,
            "context": self.context,
        }


class ScanSession:
    def __init__(self, scan_id: str, target_url: str, mode: str = "bb_mode"):
        self.scan_id = scan_id
        self.target_url = target_url
        self.mode = mode
        self.start_time = time.time()
        self.end_time: Optional[float] = None
        self.modules_executed: List[str] = []
        self.requests_count = 0
        self.payloads_count = 0
        self.findings_count = 0
        self.errors_count = 0
        self.retries_count = 0
    
    def to_dict(self) -> Dict:
        duration = (self.end_time or time.time()) - self.start_time
        return {
            "scan_id": self.scan_id,
            "target": self.target_url,
            "mode": self.mode,
            "duration_seconds": round(duration, 2),
            "modules_executed": len(self.modules_executed),
            "requests": self.requests_count,
            "payloads": self.payloads_count,
            "findings": self.findings_count,
            "errors": self.errors_count,
            "retries": self.retries_count,
        }


class LoggerManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, config: Optional[Dict] = None):
        if hasattr(self, '_initialized') and self._initialized:
            return
        
        self.config = config or {}
        self._initialized = True
        
        self.output_dir = self.config.get("log_dir", "logs")
        self.log_to_file = self.config.get("log_to_file", True)
        self.log_to_console = self.config.get("log_to_console", True)
        self.structured = self.config.get("structured_logging", True)
        
        self._scan_counter = 0
        self._request_counter = 0
        self._current_scan: Optional[ScanSession] = None
        self._trace_stack: List[TraceContext] = []
        
        self._events: List[LogEvent] = []
        self._max_events = self.config.get("max_events", 10000)
        
        self._performance_metrics: List[PerformanceMetric] = []
        self._max_metrics = self.config.get("max_metrics", 5000)
        
        self._filters: Dict[str, Any] = {}
        
        self._log_handlers: List[Callable] = []
        
        self._setup_logging()
        
        if self.log_to_file:
            self._ensure_log_dir()
    
    def _setup_logging(self):
        self.logger = logging.getLogger("BugHunter")
        self.logger.setLevel(logging.DEBUG)
        
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_format = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(console_format)
            self.logger.addHandler(console_handler)
    
    def _ensure_log_dir(self):
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
    
    def generate_scan_id(self) -> str:
        self._scan_counter += 1
        return f"SCAN-{self._scan_counter:05d}"
    
    def generate_request_id(self) -> str:
        self._request_counter += 1
        return f"REQ-{self._request_counter:06d}"
    
    def generate_correlation_id(self) -> str:
        return f"CORR-{uuid.uuid4().hex[:12].upper()}"
    
    def start_scan(self, target_url: str, mode: str = "bb_mode") -> str:
        scan_id = self.generate_scan_id()
        self._current_scan = ScanSession(scan_id, target_url, mode)
        
        self.info(
            event_type=EventType.SCAN_START,
            message=f"Starting scan {scan_id} on {target_url}",
            context={"target": target_url, "mode": mode},
            trace=TraceContext(scan_id=scan_id)
        )
        
        return scan_id
    
    def end_scan(self, findings: int = 0):
        if self._current_scan:
            self._current_scan.end_time = time.time()
            self._current_scan.findings_count = findings
            
            self.info(
                event_type=EventType.SCAN_END,
                message=f"Scan {self._current_scan.scan_id} completed",
                context=self._current_scan.to_dict(),
                trace=TraceContext(scan_id=self._current_scan.scan_id)
            )
            
            if self.log_to_file:
                self._write_scan_log()
            
            self._current_scan = None
    
    def _write_scan_log(self):
        if not self._current_scan:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.output_dir}/scan_{self._current_scan.scan_id}_{timestamp}.json"
        
        try:
            with open(filename, "w") as f:
                json.dump({
                    "session": self._current_scan.to_dict(),
                    "events": [e.to_dict() for e in self._events[-1000:]]
                }, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to write scan log: {e}")
    
    def log(
        self,
        level: str,
        event_type: EventType,
        message: str,
        context: Optional[Dict] = None,
        trace: Optional[TraceContext] = None,
        duration_ms: float = 0.0,
        status: str = "success",
        error: Optional[str] = None
    ):
        timestamp = datetime.now().isoformat()
        
        if trace is None:
            trace = TraceContext()
            if self._current_scan:
                trace.scan_id = self._current_scan.scan_id
        
        event = LogEvent(
            timestamp=timestamp,
            level=level,
            event_type=event_type.value,
            message=message,
            context=context or {},
            trace=trace,
            duration_ms=duration_ms,
            status=status,
            error=error
        )
        
        self._events.append(event)
        
        if len(self._events) > self._max_events:
            self._events = self._events[-self._max_events:]
        
        self._notify_handlers(event)
        
        if self.structured:
            self._log_structured(event)
        else:
            self._log_simple(event)
        
        if self.log_to_file:
            self._append_to_file(event)
    
    def _log_structured(self, event: LogEvent):
        if event.level == "debug":
            self.logger.debug(event.to_json())
        elif event.level == "info":
            self.logger.info(event.to_json())
        elif event.level == "warning":
            self.logger.warning(event.to_json())
        elif event.level == "error":
            self.logger.error(event.to_json())
        elif event.level == "critical":
            self.logger.critical(event.to_json())
    
    def _log_simple(self, event: LogEvent):
        msg = f"[{event.trace.scan_id}] {event.event_type}: {event.message}"
        if event.status != "success":
            msg += f" [{event.status}]"
        
        if event.level == "debug":
            self.logger.debug(msg)
        elif event.level == "info":
            self.logger.info(msg)
        elif event.level == "warning":
            self.logger.warning(msg)
        elif event.level == "error":
            self.logger.error(msg)
        elif event.level == "critical":
            self.logger.critical(msg)
    
    def _append_to_file(self, event: LogEvent):
        if not self.log_to_file:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d")
        filename = f"{self.output_dir}/bughunter_{timestamp}.jsonl"
        
        try:
            with open(filename, "a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except Exception as e:
            self.logger.error(f"Failed to write log: {e}")
    
    def debug(self, event_type: EventType, message: str, context: Optional[Dict] = None, trace: Optional[TraceContext] = None):
        self.log("debug", event_type, message, context, trace)
    
    def info(self, event_type: EventType, message: str, context: Optional[Dict] = None, trace: Optional[TraceContext] = None):
        self.log("info", event_type, message, context, trace)
    
    def warning(self, event_type: EventType, message: str, context: Optional[Dict] = None, trace: Optional[TraceContext] = None):
        self.log("warning", event_type, message, context, trace)
    
    def error(self, event_type: EventType, message: str, context: Optional[Dict] = None, trace: Optional[TraceContext] = None, error: Optional[str] = None):
        self.log("error", event_type, message, context, trace, status="error", error=error)
        
        if self._current_scan:
            self._current_scan.errors_count += 1
    
    def critical(self, event_type: EventType, message: str, context: Optional[Dict] = None, trace: Optional[TraceContext] = None, error: Optional[str] = None):
        self.log("critical", event_type, message, context, trace, status="critical", error=error)
    
    def log_module_dispatch(self, module: str, target: str, trace: Optional[TraceContext] = None):
        if self._current_scan:
            self._current_scan.modules_executed.append(module)
        
        self.info(
            event_type=EventType.MODULE_DISPATCH,
            message=f"Dispatching module {module} to {target}",
            context={"module": module, "target": target},
            trace=trace or TraceContext(module=module)
        )
    
    def log_module_complete(self, module: str, results_count: int, trace: Optional[TraceContext] = None):
        self.info(
            event_type=EventType.MODULE_COMPLETE,
            message=f"Module {module} completed with {results_count} results",
            context={"module": module, "results": results_count},
            trace=trace or TraceContext(module=module)
        )
    
    def log_payload_execution(
        self,
        payload_id: str,
        payload: str,
        module: str,
        response_time: float,
        status: str = "success",
        trace: Optional[TraceContext] = None
    ):
        if self._current_scan:
            self._current_scan.payloads_count += 1
        
        self.info(
            event_type=EventType.PAYLOAD_EXECUTED,
            message=f"Payload {payload_id} executed",
            context={
                "payload_id": payload_id,
                "payload_preview": payload[:50],
                "response_time_ms": round(response_time * 1000, 2)
            },
            trace=trace or TraceContext(payload_id=payload_id, module=module),
            duration_ms=response_time * 1000,
            status=status
        )
    
    def log_request_start(
        self,
        request_id: str,
        method: str,
        url: str,
        trace: Optional[TraceContext] = None
    ):
        if self._current_scan:
            self._current_scan.requests_count += 1
        
        self.debug(
            event_type=EventType.REQUEST_START,
            message=f"Request {request_id}: {method} {url}",
            context={"request_id": request_id, "method": method, "url": url},
            trace=trace or TraceContext(request_id=request_id)
        )
    
    def log_request_end(
        self,
        request_id: str,
        status_code: int,
        response_time: float,
        trace: Optional[TraceContext] = None
    ):
        self.debug(
            event_type=EventType.REQUEST_END,
            message=f"Request {request_id} completed with status {status_code}",
            context={
                "request_id": request_id,
                "status_code": status_code,
                "response_time_ms": round(response_time * 1000, 2)
            },
            trace=trace or TraceContext(request_id=request_id),
            duration_ms=response_time * 1000
        )
    
    def log_request_retry(
        self,
        request_id: str,
        attempt: int,
        reason: str,
        trace: Optional[TraceContext] = None
    ):
        if self._current_scan:
            self._current_scan.retries_count += 1
        
        self.warning(
            event_type=EventType.REQUEST_RETRY,
            message=f"Request {request_id} retry attempt {attempt}: {reason}",
            context={"request_id": request_id, "attempt": attempt, "reason": reason},
            trace=trace or TraceContext(request_id=request_id)
        )
    
    def log_validator_decision(
        self,
        vuln_type: str,
        decision: str,
        confidence: str,
        trace: Optional[TraceContext] = None
    ):
        self.info(
            event_type=EventType.VALIDATOR_DECISION,
            message=f"Validator decision for {vuln_type}: {decision} (confidence: {confidence})",
            context={"vuln_type": vuln_type, "decision": decision, "confidence": confidence},
            trace=trace or TraceContext(vuln_type=vuln_type)
        )
    
    def record_metric(self, name: str, value: float, unit: str = "ms", context: Optional[Dict] = None):
        metric = PerformanceMetric(
            name=name,
            value=value,
            unit=unit,
            timestamp=datetime.now().isoformat(),
            context=context or {}
        )
        
        self._performance_metrics.append(metric)
        
        if len(self._performance_metrics) > self._max_metrics:
            self._performance_metrics = self._performance_metrics[-self._max_metrics:]
    
    def get_metrics_summary(self) -> Dict:
        if not self._performance_metrics:
            return {"count": 0}
        
        by_name = {}
        for m in self._performance_metrics:
            if m.name not in by_name:
                by_name[m.name] = []
            by_name[m.name].append(m.value)
        
        summary = {"count": len(self._performance_metrics), "metrics": {}}
        for name, values in by_name.items():
            summary["metrics"][name] = {
                "count": len(values),
                "avg": round(sum(values) / len(values), 2),
                "min": round(min(values), 2),
                "max": round(max(values), 2),
                "unit": self._performance_metrics[0].unit
            }
        
        return summary
    
    def get_events_summary(self) -> Dict:
        by_type = {}
        by_level = {}
        
        for e in self._events:
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
            by_level[e.level] = by_level.get(e.level, 0) + 1
        
        return {
            "total": len(self._events),
            "by_type": by_type,
            "by_level": by_level
        }
    
    def add_filter(self, key: str, value: Any):
        self._filters[key] = value
    
    def clear_filters(self):
        self._filters.clear()
    
    def get_filtered_events(
        self,
        scan_id: Optional[str] = None,
        module: Optional[str] = None,
        level: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        filtered = []
        
        for event in self._events:
            if scan_id and event.trace.scan_id != scan_id:
                continue
            if module and event.trace.module != module:
                continue
            if level and event.level != level:
                continue
            if event_type and event.event_type != event_type:
                continue
            
            filtered.append(event.to_dict())
            
            if len(filtered) >= limit:
                break
        
        return filtered
    
    def register_handler(self, handler: Callable):
        if handler not in self._log_handlers:
            self._log_handlers.append(handler)
    
    def _notify_handlers(self, event: LogEvent):
        for handler in self._log_handlers:
            try:
                handler(event)
            except Exception:
                pass
    
    def get_scan_stats(self) -> Dict:
        if not self._current_scan:
            return {"active": False}
        
        return {
            "active": True,
            "scan_id": self._current_scan.scan_id,
            "target": self._current_scan.target_url,
            "mode": self._current_scan.mode,
            "duration_seconds": round(time.time() - self._current_scan.start_time, 2),
            "modules_executed": len(self._current_scan.modules_executed),
            "requests": self._current_scan.requests_count,
            "payloads": self._current_scan.payloads_count,
            "findings": self._current_scan.findings_count,
            "errors": self._current_scan.errors_count,
            "retries": self._current_scan.retries_count,
        }
    
    def get_logger(self) -> logging.Logger:
        return self.logger
    
    def close(self):
        if self._current_scan:
            self.end_scan()


_logger_instance: Optional[LoggerManager] = None


def get_logger_manager(config: Optional[Dict] = None) -> LoggerManager:
    global _logger_instance
    
    if _logger_instance is None:
        _logger_instance = LoggerManager(config)
    
    return _logger_instance


def reset_logger_manager():
    global _logger_instance
    _logger_instance = None


async def log_execution(context: Optional[TraceContext], event_type: EventType, message: str, **kwargs):
    manager = get_logger_manager()
    manager.log("info", event_type, message, trace=context, **kwargs)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("\n=== Logger Manager Test ===\n")
    
    manager = get_logger_manager({"log_to_file": False})
    
    scan_id = manager.start_scan("https://example.com", "bb_mode")
    print(f"Started scan: {scan_id}")
    
    trace = TraceContext(
        scan_id=scan_id,
        request_id=manager.generate_request_id(),
        payload_id="xss_bas_001",
        module="xss"
    )
    
    manager.log_module_dispatch("xss", "https://example.com/login", trace)
    manager.log_payload_execution("xss_bas_001", "<script>alert(1)</script>", "xss", 0.124, trace)
    manager.log_request_start(trace.request_id, "GET", "https://example.com", trace)
    manager.log_request_end(trace.request_id, 200, 0.124, trace)
    manager.log_validator_decision("xss", "confirmed", "high", trace)
    
    manager.record_metric("request_time", 0.124, "ms", {"module": "xss"})
    
    print("\n=== Scan Stats ===")
    print(manager.get_scan_stats())
    
    print("\n=== Events Summary ===")
    print(manager.get_events_summary())
    
    print("\n=== Metrics Summary ===")
    print(manager.get_metrics_summary())
    
    manager.end_scan(findings=2)
    print("\nScan completed")