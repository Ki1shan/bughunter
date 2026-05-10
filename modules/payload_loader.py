"""
BugHunter AI Elite - Payload Loader Module
Centralized payload loading system with caching and validation
"""

import json
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PayloadLevel(Enum):
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    DANGEROUS = "dangerous"
    MANUAL = "manual"


class PayloadModule(Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    SSTI = "ssti"
    XXE = "xxe"
    COMMAND_INJECTION = "command_injection"
    OPEN_REDIRECT = "open_redirect"
    PATH_TRAVERSAL = "path_traversal"
    JWT = "jwt"
    IDOR = "idor"
    GRAPHQL = "graphql"
    CSRF = "csrf"
    DESERIALIZATION = "deserialization"
    RACE_CONDITIONS = "race_conditions"


PAYLOAD_SCHEMA = {
    "required": ["payload", "type", "level", "payload_id"],
    "optional": ["context", "safe", "tags", "description", "confidence"]
}

DEFAULT_PAYLOAD_STRUCTURE = {
    "payload": "",
    "type": "",
    "level": "basic",
    "payload_id": "",
    "context": "generic",
    "safe": True,
    "tags": [],
    "description": "",
    "confidence": "medium"
}


@dataclass
class PayloadEntry:
    payload: str
    type: str
    level: str = "basic"
    payload_id: str = ""
    context: str = "generic"
    safe: bool = True
    tags: List[str] = field(default_factory=list)
    description: str = ""
    confidence: str = "medium"
    
    def to_dict(self) -> Dict:
        data = {
            "payload": self.payload,
            "type": self.type,
            "level": self.level,
            "payload_id": self.payload_id,
            "context": self.context,
            "safe": self.safe,
            "tags": self.tags,
            "description": self.description,
            "confidence": self.confidence
        }
        if self.payload_id:
            data["payload_id"] = self.payload_id
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> "PayloadEntry":
        return cls(
            payload=data.get("payload", ""),
            type=data.get("type", ""),
            level=data.get("level", "basic"),
            payload_id=data.get("payload_id", ""),
            context=data.get("context", "generic"),
            safe=data.get("safe", True),
            tags=data.get("tags", []),
            description=data.get("description", ""),
            confidence=data.get("confidence", "medium")
        )


@dataclass
class PayloadModuleData:
    module_name: str
    levels: Dict[str, List[PayloadEntry]] = field(default_factory=dict)
    loaded: bool = False
    
    def all_payloads(self) -> List[PayloadEntry]:
        payloads = []
        for level_data in self.levels.values():
            payloads.extend(level_data)
        return payloads
    
    def get_by_level(self, level: str) -> List[PayloadEntry]:
        return self.levels.get(level, [])
    
    def count(self) -> int:
        return sum(len(p) for p in self.levels.values())


class PayloadLoader:
    def __init__(self, payloads_dir: str = "payloads"):
        self.payloads_dir = Path(payloads_dir)
        self._cache: Dict[str, PayloadModuleData] = {}
        self._load_attempts: Dict[str, bool] = {}
        self._schema_version = "1.0"
        
    def _validate_payload(self, payload_data: Dict, module: str, level: str = "basic", index: int = 0) -> Optional[PayloadEntry]:
        if not payload_data.get("payload"):
            return None
        
        payload_str = str(payload_data.get("payload", ""))
        if not payload_str.strip():
            return None
        
        module_short = module.lower()[:4] if module else "unk"
        existing_id = payload_data.get("payload_id", "")
        
        if not existing_id:
            pid = f"{module_short}_{level[:3]}_{index:03d}"
        else:
            pid = existing_id
        
        entry = PayloadEntry(
            payload=payload_str,
            type=module,
            level=level,
            payload_id=pid,
            context=payload_data.get("context", "generic"),
            safe=payload_data.get("safe", True),
            tags=payload_data.get("tags", []),
            description=payload_data.get("description", ""),
            confidence=payload_data.get("confidence", "medium")
        )
        
        return entry
    
    def _load_json_file(self, file_path: Path) -> List[PayloadEntry]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            if isinstance(data, list):
                payloads = []
                for idx, item in enumerate(data):
                    entry = self._validate_payload(item, "", "basic", idx)
                    if entry:
                        payloads.append(entry)
                return payloads
            
            elif isinstance(data, dict):
                payloads = data.get("payloads", [])
                module = data.get("type", "")
                level = data.get("level", "basic")
                entries = []
                for idx, item in enumerate(payloads):
                    entry = self._validate_payload(item, module, level, idx)
                    if entry:
                        entries.append(entry)
                return entries
            
            return []
            
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {file_path}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return []
    
    def _parse_txt_file(self, file_path: Path, module: str, level: str) -> List[PayloadEntry]:
        payloads = []
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            lines = content.split("\n")
            current_context = "generic"
            module_short = module[:4] if module else "unk"
            
            for idx, line in enumerate(lines):
                line = line.strip()
                
                if not line or line.startswith("=") or line.startswith("#") or line.startswith("---"):
                    continue
                
                if any(ctx in line.upper() for ctx in ["PAYLOADS", "BASIC", "INTERMEDIATE", "ADVANCED", "DANGEROUS", "MANUAL", "ATTRIBUTE", "JAVASCRIPT", "HTML", "SCRIPT"]):
                    if "BASIC" in line.upper():
                        current_context = "basic"
                    elif "INTERMEDIATE" in line.upper():
                        current_context = "intermediate"
                    elif "ADVANCED" in line.upper():
                        current_context = "advanced"
                    elif "DANGEROUS" in line.upper():
                        current_context = "dangerous"
                    elif "MANUAL" in line.upper():
                        current_context = "manual"
                    elif "ATTRIBUTE" in line.upper():
                        current_context = "attribute"
                    elif "JAVASCRIPT" in line.upper():
                        current_context = "javascript"
                    elif "HTML" in line.upper():
                        current_context = "html"
                    continue
                
                payload_str = line.split("–")[0].split("-")[0].strip()
                if not payload_str or len(payload_str) < 2:
                    continue
                
                desc = ""
                if "–" in line or "-" in line:
                    parts = line.split("–") if "–" in line else line.split("-")
                    if len(parts) > 1:
                        desc = parts[-1].strip()
                
                safe = level in ["basic", "intermediate", "manual"]
                pid = f"{module_short}_{level[:3]}_{idx:03d}"
                
                entry = PayloadEntry(
                    payload=payload_str,
                    type=module,
                    level=level,
                    payload_id=pid,
                    context=current_context,
                    safe=safe,
                    tags=[current_context],
                    description=desc,
                    confidence="medium"
                )
                payloads.append(entry)
                
        except Exception as e:
            logger.error(f"Error parsing TXT {file_path}: {e}")
        
        return payloads
    
    def _discover_module_dirs(self) -> List[str]:
        modules = []
        
        if not self.payloads_dir.exists():
            logger.warning(f"Payloads directory not found: {self.payloads_dir}")
            return modules
        
        for item in self.payloads_dir.iterdir():
            if item.is_dir() and item.name not in ["__pycache__", "modules"]:
                modules.append(item.name)
        
        for file in self.payloads_dir.glob("*.txt"):
            name = file.stem
            
            replacements = [
                ("-Payloads", ""),
                ("_Payloads", ""),
                ("_PAYLOADS", ""),
                ("-Payload", ""),
                ("_Payload", ""),
            ]
            
            module_name = name
            for old, new in replacements:
                if old in name:
                    module_name = name.replace(old, "").lower()
                    break
                if new in name:
                    module_name = name.replace(new, "").lower()
                    break
            
            if not module_name:
                module_name = name.lower()
            
            if module_name not in modules:
                modules.append(module_name)
        
        for file in self.payloads_dir.glob("*.json"):
            if file.name != "payloads.json":
                module_name = file.stem.lower()
                if module_name and module_name not in modules:
                    modules.append(module_name)
        
        return sorted(set(modules))
    
    def load_module(self, module: str, force: bool = False) -> PayloadModuleData:
        cache_key = module.lower()
        
        if cache_key in self._cache and not force:
            return self._cache[cache_key]
        
        if cache_key in self._load_attempts and self._load_attempts[cache_key]:
            return PayloadModuleData(module_name=module)
        
        module_data = PayloadModuleData(module_name=module)
        
        module_lower = module.lower()
        
        all_txt_files = {}
        for f in self.payloads_dir.glob("*.txt"):
            name = f.stem
            for suffix in ["-Payloads", "-PAYLOADS", "_Payloads", "-Payload", "_Payload"]:
                if name.endswith(suffix):
                    name = name[:-len(suffix)]
                    break
            all_txt_files[name.lower()] = f
        
        all_json_files = {}
        for f in self.payloads_dir.glob("*.json"):
            if f.name != "payloads.json":
                all_json_files[f.stem.lower()] = f
        
        found_payloads = False
        
        if module_lower in all_txt_files:
            txt_file = all_txt_files[module_lower]
            for level in [PayloadLevel.BASIC, PayloadLevel.INTERMEDIATE, PayloadLevel.ADVANCED, PayloadLevel.DANGEROUS, PayloadLevel.MANUAL]:
                entries = self._parse_txt_file(txt_file, module_lower, level.value)
                if entries:
                    module_data.levels[level.value] = entries
                    found_payloads = True
                    break
        
        if not found_payloads and module_lower in all_json_files:
            json_file = all_json_files[module_lower]
            entries = self._load_json_file(json_file)
            if entries:
                module_data.levels["basic"] = entries
                found_payloads = True
        
        module_data.loaded = True
        self._cache[cache_key] = module_data
        self._load_attempts[cache_key] = True
        
        logger.info(f"Loaded module '{module}': {module_data.count()} payloads")
        
        return module_data
    
    def load_payloads(
        self,
        module: str,
        level: Optional[str] = None,
        safe_only: bool = False,
        limit: Optional[int] = None
    ) -> List[PayloadEntry]:
        module_data = self.load_module(module)
        
        if level:
            payloads = module_data.get_by_level(level)
        else:
            payloads = module_data.all_payloads()
        
        if safe_only:
            payloads = [p for p in payloads if p.safe]
        
        if limit:
            payloads = payloads[:limit]
        
        return payloads
    
    def get_payload_values(
        self,
        module: str,
        level: Optional[str] = None,
        safe_only: bool = False,
        limit: Optional[int] = None
    ) -> List[str]:
        payloads = self.load_payloads(module, level, safe_only, limit)
        return [p.payload for p in payloads]
    
    def list_modules(self) -> List[str]:
        return self._discover_module_dirs()
    
    def get_module_info(self, module: str) -> Dict:
        module_data = self.load_module(module)
        
        info = {
            "module": module,
            "loaded": module_data.loaded,
            "total": module_data.count(),
            "levels": {}
        }
        
        for level, payloads in module_data.levels.items():
            safe_count = sum(1 for p in payloads if p.safe)
            info["levels"][level] = {
                "count": len(payloads),
                "safe": safe_count,
                "unsafe": len(payloads) - safe_count
            }
        
        return info
    
    def preload_all(self) -> Dict[str, Dict]:
        modules = self.list_modules()
        results = {}
        
        for module in modules:
            results[module] = self.get_module_info(module)
        
        return results
    
    def clear_cache(self, module: Optional[str] = None):
        if module:
            cache_key = module.lower()
            if cache_key in self._cache:
                del self._cache[cache_key]
            if cache_key in self._load_attempts:
                del self._load_attempts[cache_key]
        else:
            self._cache.clear()
            self._load_attempts.clear()
        
        logger.info(f"Cache cleared for: {module or 'all'}")
    
    def validate_structure(self) -> Dict[str, any]:
        results = {
            "directory_exists": self.payloads_dir.exists(),
            "modules_found": [],
            "errors": [],
            "warnings": []
        }
        
        if not results["directory_exists"]:
            results["errors"].append(f"Payloads directory not found: {self.payloads_dir}")
            return results
        
        modules = self.list_modules()
        results["modules_found"] = modules
        
        for module in modules:
            try:
                info = self.get_module_info(module)
                if info["total"] == 0:
                    results["warnings"].append(f"Module '{module}' has no payloads")
            except Exception as e:
                results["errors"].append(f"Module '{module}' failed to load: {e}")
        
        return results


_loader_instance: Optional[PayloadLoader] = None


def get_payload_loader(payloads_dir: str = "payloads") -> PayloadLoader:
    global _loader_instance
    
    if _loader_instance is None:
        _loader_instance = PayloadLoader(payloads_dir)
    
    return _loader_instance


def load_payloads(
    module: str,
    level: Optional[str] = None,
    safe_only: bool = False,
    limit: Optional[int] = None
) -> List[str]:
    loader = get_payload_loader()
    return loader.get_payload_values(module, level, safe_only, limit)


def load_payload_entries(
    module: str,
    level: Optional[str] = None,
    safe_only: bool = False,
    limit: Optional[int] = None
) -> List[PayloadEntry]:
    loader = get_payload_loader()
    return loader.load_payloads(module, level, safe_only, limit)


def list_payload_modules() -> List[str]:
    loader = get_payload_loader()
    return loader.list_modules()


def preload_payloads() -> Dict[str, Dict]:
    loader = get_payload_loader()
    return loader.preload_all()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    loader = get_payload_loader()
    
    print("\n=== BugHunter AI Elite - Payload Loader ===\n")
    
    modules = loader.list_modules()
    print(f"Available modules ({len(modules)}): {modules}\n")
    
    for module in modules:
        info = loader.get_module_info(module)
        print(f"[{module}]")
        print(f"  Total: {info['total']}")
        for level, stats in info["levels"].items():
            print(f"    {level}: {stats['count']} ({stats['safe']} safe)")
        print()