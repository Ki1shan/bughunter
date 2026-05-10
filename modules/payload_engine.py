"""
BugHunter AI Elite - Payload Engine
Centralized payload loading system (backward compatible wrapper)
"""

from enum import Enum
from typing import List, Dict, Optional

try:
    from modules.payload_loader import (
        PayloadLoader,
        PayloadLevel,
        get_payload_loader,
        load_payloads as _load_payloads,
        load_payload_entries
    )
    _HAS_NEW_LOADER = True
except ImportError:
    _HAS_NEW_LOADER = False


class PayloadLevel(Enum):
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    DANGEROUS = "dangerous"
    MANUAL = "manual"


class ExecutionMode(Enum):
    BB_MODE = "bb_mode"
    AGGRESSIVE = "aggressive"
    LAB_MODE = "lab_mode"


class PayloadEngine:
    def __init__(self, payloads_dir: str = "payloads"):
        self.payloads_dir = payloads_dir
        self.mode = ExecutionMode.BB_MODE
        self._loader = None
        
        if _HAS_NEW_LOADER:
            self._loader = get_payload_loader(payloads_dir)
    
    @property
    def loader(self) -> Optional[PayloadLoader]:
        return self._loader
        
    def load_payloads(self, module: str, level: PayloadLevel = None) -> List[Dict]:
        if self._loader and _HAS_NEW_LOADER:
            level_str = level.value if level else None
            entries = self._loader.load_payloads(module, level_str)
            return [e.to_dict() for e in entries]
        return []
    
    def get_payloads_for_module(
        self, 
        module: str, 
        count: int = 10,
        risk_max: int = 3
    ) -> List[str]:
        if self._loader and _HAS_NEW_LOADER:
            safe_only = risk_max <= 2
            return self._loader.get_payload_values(module, safe_only=safe_only, limit=count)
        return []
    
    def list_available_modules(self) -> List[str]:
        if self._loader and _HAS_NEW_LOADER:
            return self._loader.list_modules()
        return []
    
    def get_module_info(self, module: str) -> Dict:
        if self._loader and _HAS_NEW_LOADER:
            return self._loader.get_module_info(module)
        return {"levels": {}}


def load_payload_engine(payloads_dir: str = "payloads") -> PayloadEngine:
    return PayloadEngine(payloads_dir)


def load_payloads(
    module: str,
    level: Optional[str] = None,
    safe_only: bool = False,
    limit: Optional[int] = None
) -> List[str]:
    if _HAS_NEW_LOADER:
        return _load_payloads(module, level, safe_only, limit)
    return []


if __name__ == "__main__":
    engine = load_payload_engine()
    print("Available modules:", engine.list_available_modules())
    
    for module in engine.list_available_modules():
        info = engine.get_module_info(module)
        if isinstance(info, dict):
            total = info.get("total", 0)
            print(f"  {module}: {total} payloads")