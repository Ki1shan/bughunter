"""
BugHunter AI Elite - Mode Manager
Centralized execution policy and governance system.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum

logger = logging.getLogger(__name__)


class ExecutionMode(Enum):
    BB_MODE = "bb_mode"
    AGGRESSIVE = "aggressive"
    LAB_MODE = "lab_mode"


class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DANGEROUS = "dangerous"


class PayloadRisk(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DANGEROUS = "dangerous"


@dataclass
class ModePolicy:
    mode: str
    allow_dangerous_payloads: bool = False
    allow_destructive: bool = False
    max_concurrency: int = 5
    max_crawl_depth: int = 2
    max_requests: int = 100
    max_timeout: int = 30
    safe_payload_levels: List[str] = field(default_factory=list)
    blocked_payload_patterns: List[str] = field(default_factory=list)
    blocked_modules: List[str] = field(default_factory=list)
    allowed_modules: List[str] = field(default_factory=list)
    rate_limit_rps: float = 5.0
    rate_limit_rpm: float = 50.0
    enable_crawling: bool = True
    enable_deep_scan: bool = False
    enable_chaining: bool = False
    enable_oob: bool = False
    enable_auth_simulation: bool = False
    allow_reflection_based: bool = True
    allow_time_based: bool = True
    allow_blind: bool = False
    scan_timeout: int = 300
    endpoint_limit: int = 50
    
    def to_dict(self) -> Dict:
        return {
            "mode": self.mode,
            "allow_dangerous_payloads": self.allow_dangerous_payloads,
            "allow_destructive": self.allow_destructive,
            "max_concurrency": self.max_concurrency,
            "max_crawl_depth": self.max_crawl_depth,
            "max_requests": self.max_requests,
            "max_timeout": self.max_timeout,
            "safe_payload_levels": self.safe_payload_levels,
            "blocked_payload_patterns": self.blocked_payload_patterns,
            "blocked_modules": self.blocked_modules,
            "allowed_modules": self.allowed_modules,
            "rate_limit_rps": self.rate_limit_rps,
            "rate_limit_rpm": self.rate_limit_rpm,
            "enable_crawling": self.enable_crawling,
            "enable_deep_scan": self.enable_deep_scan,
            "enable_chaining": self.enable_chaining,
            "enable_oob": self.enable_oob,
            "enable_auth_simulation": self.enable_auth_simulation,
            "allow_reflection_based": self.allow_reflection_based,
            "allow_time_based": self.allow_time_based,
            "allow_blind": self.allow_blind,
            "scan_timeout": self.scan_timeout,
            "endpoint_limit": self.endpoint_limit,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ModePolicy":
        return cls(**data)


@dataclass
class PayloadClassification:
    payload_id: str = ""
    payload: str = ""
    risk_level: str = "low"
    is_dangerous: bool = False
    is_destructive: bool = False
    can_reflect: bool = False
    can_time_based: bool = False
    is_blind: bool = False
    is_stacked: bool = False
    is_oob: bool = False
    is_shell: bool = False
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "payload_id": self.payload_id,
            "payload": self.payload,
            "risk_level": self.risk_level,
            "is_dangerous": self.is_dangerous,
            "is_destructive": self.is_destructive,
            "can_reflect": self.can_reflect,
            "can_time_based": self.can_time_based,
            "is_blind": self.is_blind,
            "is_stacked": self.is_stacked,
            "is_oob": self.is_oob,
            "is_shell": self.is_shell,
            "tags": self.tags,
        }


class ModeManager:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._modes: Dict[str, ModePolicy] = {}
        self._current_mode = ExecutionMode.BB_MODE
        self._initialized = False
        self._load_default_modes()
    
    def _load_default_modes(self):
        self._modes["bb_mode"] = ModePolicy(
            mode="bb_mode",
            allow_dangerous_payloads=False,
            allow_destructive=False,
            max_concurrency=5,
            max_crawl_depth=2,
            max_requests=100,
            max_timeout=30,
            safe_payload_levels=["basic", "intermediate"],
            blocked_payload_patterns=[
                "rm -rf",
                "DROP TABLE",
                "DELETE FROM",
                "TRUNCATE",
                "format c:",
                "del /f",
                "mkfs",
                "shutdown",
                "reboot",
                "init 0",
                "poweroff",
            ],
            blocked_modules=["deserialization", "race_conditions"],
            rate_limit_rps=5.0,
            rate_limit_rpm=50.0,
            enable_crawling=True,
            enable_deep_scan=False,
            enable_chaining=False,
            enable_oob=False,
            enable_auth_simulation=False,
            allow_reflection_based=True,
            allow_time_based=True,
            allow_blind=False,
            scan_timeout=300,
            endpoint_limit=50,
        )
        
        self._modes["aggressive"] = ModePolicy(
            mode="aggressive",
            allow_dangerous_payloads=True,
            allow_destructive=False,
            max_concurrency=10,
            max_crawl_depth=3,
            max_requests=200,
            max_timeout=45,
            safe_payload_levels=["basic", "intermediate", "advanced"],
            blocked_payload_patterns=[
                "rm -rf",
                "DROP TABLE",
                "DELETE FROM",
                "TRUNCATE",
            ],
            blocked_modules=[],
            rate_limit_rps=10.0,
            rate_limit_rpm=150.0,
            enable_crawling=True,
            enable_deep_scan=True,
            enable_chaining=True,
            enable_oob=True,
            enable_auth_simulation=True,
            allow_reflection_based=True,
            allow_time_based=True,
            allow_blind=True,
            scan_timeout=600,
            endpoint_limit=100,
        )
        
        self._modes["lab_mode"] = ModePolicy(
            mode="lab_mode",
            allow_dangerous_payloads=True,
            allow_destructive=True,
            max_concurrency=20,
            max_crawl_depth=5,
            max_requests=500,
            max_timeout=60,
            safe_payload_levels=["basic", "intermediate", "advanced", "dangerous", "manual"],
            blocked_payload_patterns=[],
            blocked_modules=[],
            rate_limit_rps=20.0,
            rate_limit_rpm=500.0,
            enable_crawling=True,
            enable_deep_scan=True,
            enable_chaining=True,
            enable_oob=True,
            enable_auth_simulation=True,
            allow_reflection_based=True,
            allow_time_based=True,
            allow_blind=True,
            scan_timeout=1800,
            endpoint_limit=250,
        )
        
        self._initialized = True
    
    def get_mode_policy(self, mode: str) -> Optional[ModePolicy]:
        key = mode.lower().replace("-", "_")
        if key == "bbmode":
            key = "bb_mode"
        elif key == "bb_mode":
            key = "bb_mode"
        elif key == "aggressive":
            key = "aggressive"
        elif key == "lab":
            key = "lab_mode"
        elif key == "lab_mode":
            key = "lab_mode"
        return self._modes.get(key)
    
    def get_current_policy(self) -> ModePolicy:
        return self.get_mode_policy(self._current_mode.value) or self._modes["bb_mode"]
    
    def set_mode(self, mode: str) -> bool:
        policy = self.get_mode_policy(mode)
        if policy:
            self._current_mode = ExecutionMode(mode)
            logger.info(f"Mode set to: {mode}")
            return True
        return False
    
    def get_current_mode(self) -> ExecutionMode:
        return self._current_mode
    
    def is_payload_allowed(self, payload: str, module: str = "") -> tuple[bool, str]:
        policy = self.get_current_policy()
        payload_lower = payload.lower()
        
        if policy.blocked_payload_patterns:
            for pattern in policy.blocked_payload_patterns:
                if pattern.lower() in payload_lower:
                    return False, f"Payload matches blocked pattern: {pattern}"
        
        if not policy.allow_dangerous_payloads:
            classification = self.classify_payload(payload)
            if classification.is_dangerous:
                return False, f"Payload classified as dangerous: {classification.risk_level}"
        
        if policy.safe_payload_levels:
            allowed_levels = set(policy.safe_payload_levels)
        
        return True, "allowed"
    
    def classify_payload(self, payload: str) -> PayloadClassification:
        classification = PayloadClassification(payload=payload)
        payload_lower = payload.lower()
        tags = []
        is_dangerous = False
        is_destructive = False
        
        dangerous_patterns = [
            "eval(", "exec(", "system(", "shell_exec",
            "passthru", "proc_open", "popen(",
            "<script", "javascript:", "onerror=",
            "onload=", "onclick=",
        ]
        
        destructive_patterns = [
            "rm -rf", "del /f", "format c:",
            "DROP TABLE", "DELETE FROM", "TRUNCATE",
            "DROP DATABASE", "DROP SCHEMA",
            "shutdown", "reboot", "poweroff",
        ]
        
        stacked_patterns = [
            "; DROP", "; DELETE", "; TRUNCATE",
            " AND ", " OR ",
        ]
        
        oob_patterns = [
            "sleep(", "benchmark(", "WAITFOR",
            "exec xp_", "EXEC sp_",
            "LOAD_FILE", "INTO OUTFILE",
        ]
        
        shell_patterns = [
            "/bin/sh", "/bin/bash", "cmd.exe",
            "powershell", "wget", "curl",
        ]
        
        time_patterns = [
            "sleep", "benchmark", "WAITFOR",
            "pg_sleep", "delay",
        ]
        
        reflect_patterns = [
            "<script", "javascript:", "onerror=",
            "onload=", "svg onload",
            "<img src", "<iframe",
        ]
        
        blind_patterns = [
            "AND (SELECT", "OR (SELECT",
            "WAITFOR", "BENCHMARK",
            "sleep", "benchmark",
        ]
        
        for pattern in dangerous_patterns:
            if pattern in payload_lower:
                tags.append("dangerous")
                is_dangerous = True
                break
        
        for pattern in destructive_patterns:
            if pattern in payload_lower:
                tags.append("destructive")
                is_destructive = True
                is_dangerous = True
                break
        
        for pattern in stacked_patterns:
            if pattern in payload_lower:
                tags.append("stacked")
                classification.is_stacked = True
                break
        
        for pattern in oob_patterns:
            if pattern in payload_lower:
                tags.append("oob")
                classification.is_oob = True
                break
        
        for pattern in shell_patterns:
            if pattern in payload_lower:
                tags.append("shell")
                classification.is_shell = True
                break
        
        for pattern in time_patterns:
            if pattern in payload_lower:
                tags.append("time_based")
                classification.can_time_based = True
                break
        
        for pattern in reflect_patterns:
            if pattern in payload_lower:
                tags.append("reflect")
                classification.can_reflect = True
                break
        
        for pattern in blind_patterns:
            if pattern in payload_lower:
                tags.append("blind")
                classification.is_blind = True
                break
        
        classification.tags = tags
        classification.is_dangerous = is_dangerous
        classification.is_destructive = is_destructive
        
        if is_destructive:
            classification.risk_level = "dangerous"
        elif is_dangerous or classification.is_shell:
            classification.risk_level = "high"
        elif classification.is_oob or classification.is_blind:
            classification.risk_level = "medium"
        elif classification.can_reflect:
            classification.risk_level = "low"
        else:
            classification.risk_level = "safe"
        
        return classification
    
    def is_module_allowed(self, module_name: str) -> tuple[bool, str]:
        policy = self.get_current_policy()
        
        if policy.blocked_modules:
            if module_name in policy.blocked_modules:
                return False, f"Module '{module_name}' is blocked in {policy.mode}"
        
        if policy.allowed_modules:
            if module_name not in policy.allowed_modules:
                return False, f"Module '{module_name}' not in allowed list for {policy.mode}"
        
        return True, "allowed"
    
    def get_execution_config(self) -> Dict:
        policy = self.get_current_policy()
        
        return {
            "max_concurrency": policy.max_concurrency,
            "rate_limit_rps": policy.rate_limit_rps,
            "rate_limit_rpm": policy.rate_limit_rpm,
            "max_requests": policy.max_requests,
            "max_timeout": policy.max_timeout,
            "enable_crawling": policy.enable_crawling,
            "enable_deep_scan": policy.enable_deep_scan,
            "scan_timeout": policy.scan_timeout,
            "endpoint_limit": policy.endpoint_limit,
        }
    
    def get_module_restrictions(self, module_name: str) -> Dict:
        policy = self.get_current_policy()
        
        restrictions = {
            "can_use_reflection": policy.allow_reflection_based,
            "can_use_time_based": policy.allow_time_based,
            "can_use_blind": policy.allow_blind,
            "can_use_oob": policy.enable_oob,
            "max_depth": policy.max_crawl_depth if module_name in ["crawler", "attack_surface"] else None,
        }
        
        return restrictions
    
    def should_allow_module(self, module_name: str) -> bool:
        policy = self.get_current_policy()
        
        if policy.blocked_modules:
            return module_name not in policy.blocked_modules
        
        if policy.allowed_modules:
            return module_name in policy.allowed_modules
        
        return True
    
    def get_safe_payload_levels(self) -> List[str]:
        policy = self.get_current_policy()
        return policy.safe_payload_levels.copy()
    
    def can_use_payload_level(self, level: str) -> bool:
        policy = self.get_current_policy()
        return level in policy.safe_payload_levels
    
    def get_rate_limits(self) -> Dict:
        policy = self.get_current_policy()
        return {
            "requests_per_second": policy.rate_limit_rps,
            "requests_per_minute": policy.rate_limit_rpm,
            "max_concurrent": policy.max_concurrency,
        }
    
    def get_scan_limits(self) -> Dict:
        policy = self.get_current_policy()
        return {
            "max_crawl_depth": policy.max_crawl_depth,
            "max_requests": policy.max_requests,
            "max_timeout": policy.max_timeout,
            "scan_timeout": policy.scan_timeout,
            "endpoint_limit": policy.endpoint_limit,
            "enable_crawling": policy.enable_crawling,
            "enable_deep_scan": policy.enable_deep_scan,
        }
    
    def get_mode_info(self, mode: str) -> Optional[Dict]:
        policy = self.get_mode_policy(mode)
        if policy:
            return policy.to_dict()
        return None
    
    def list_modes(self) -> List[str]:
        return list(self._modes.keys())
    
    def update_mode_policy(self, mode: str, updates: Dict) -> bool:
        policy = self.get_mode_policy(mode)
        if not policy:
            return False
        
        for key, value in updates.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
        
        return True
    
    def get_status(self) -> Dict:
        return {
            "current_mode": self._current_mode.value,
            "available_modes": list(self._modes.keys()),
            "policy": self.get_current_policy().to_dict(),
        }


_mode_instance: Optional[ModeManager] = None


def get_mode_manager(config: Optional[Dict] = None) -> ModeManager:
    global _mode_instance
    
    if _mode_instance is None:
        _mode_instance = ModeManager(config)
    
    return _mode_instance


def reset_mode_manager():
    global _mode_instance
    _mode_instance = None


def set_execution_mode(mode: str) -> bool:
    manager = get_mode_manager()
    return manager.set_mode(mode)


def get_current_mode() -> str:
    manager = get_mode_manager()
    return manager.get_current_mode().value


def is_payload_allowed(payload: str) -> tuple[bool, str]:
    manager = get_mode_manager()
    return manager.is_payload_allowed(payload)


def is_module_allowed(module: str) -> tuple[bool, str]:
    manager = get_mode_manager()
    return manager.is_module_allowed(module)


def get_execution_policy() -> Dict:
    manager = get_mode_manager()
    return manager.get_execution_config()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    manager = get_mode_manager()
    
    print("\n=== Mode Manager Status ===\n")
    
    status = manager.get_status()
    print(f"Current mode: {status['current_mode']}")
    print(f"Available modes: {status['available_modes']}")
    
    policy = status['policy']
    print(f"\n=== Current Policy ===")
    print(f"Max concurrency: {policy['max_concurrency']}")
    print(f"Max crawl depth: {policy['max_crawl_depth']}")
    print(f"Safe payload levels: {policy['safe_payload_levels']}")
    print(f"Rate limit (rps): {policy['rate_limit_rps']}")
    
    print(f"\n=== Payload Classification ===")
    
    test_payloads = [
        "<script>alert(1)</script>",
        "' OR '1'='1",
        "sleep(5)",
        "; rm -rf /",
        "1 AND SLEEP(5)--",
    ]
    
    for payload in test_payloads:
        classification = manager.classify_payload(payload)
        allowed, reason = manager.is_payload_allowed(payload)
        print(f"\nPayload: {payload}")
        print(f"  Risk: {classification.risk_level}")
        print(f"  Tags: {classification.tags}")
        print(f"  Allowed in current mode: {allowed} ({reason})")