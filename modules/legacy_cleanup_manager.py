"""
BugHunter AI Elite - Legacy Cleanup Manager
Architecture consolidation and migration tracking system.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from enum import Enum

logger = logging.getLogger(__name__)


class ComponentStatus(Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    MIGRATED = "migrated"
    REMOVED = "removed"
    PENDING = "pending"


class LegacyCategory(Enum):
    EXECUTION_REMNANT = "execution_remnant"
    DEPRECATED_WRAPPER = "deprecated_wrapper"
    DUPLICATE_PATH = "duplicate_path"
    COMPATIBILITY_BRIDGE = "compatibility_bridge"
    LEGACY_PAYLOAD = "legacy_payload"
    OUTDATED_ROUTING = "outdated_routing"
    TRANSITIONAL_HELPER = "transitional_helper"


@dataclass
class LegacyComponent:
    name: str
    category: str
    status: str = ComponentStatus.ACTIVE.value
    replacement: str = ""
    safe_to_remove: bool = False
    migration_coverage: float = 0.0
    files_using: List[str] = field(default_factory=list)
    last_activity: str = ""
    deprecation_warning: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "replacement": self.replacement,
            "safe_to_remove": self.safe_to_remove,
            "migration_coverage": self.migration_coverage,
            "files_using": self.files_using,
            "last_activity": self.last_activity,
            "deprecation_warning": self.deprecation_warning,
        }


@dataclass
class ArchitectureCheck:
    name: str
    passed: bool = True
    issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "passed": self.passed,
            "issues": self.issues,
            "warnings": self.warnings,
            "timestamp": self.timestamp,
        }


class LegacyCleanupManager:
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
        
        self._legacy_components: Dict[str, LegacyComponent] = {}
        self._migration_log: List[Dict] = []
        self._integrity_checks: List[ArchitectureCheck] = []
        self._max_log_entries = 1000
        
        self._initialize_legacy_components()
    
    def _initialize_legacy_components(self):
        self._legacy_components["direct_httpx"] = LegacyComponent(
            name="direct_httpx",
            category=LegacyCategory.EXECUTION_REMNANT.value,
            replacement="execution_controller",
            safe_to_remove=False,
            migration_coverage=68.0,
            files_using=[],
            deprecation_warning="Direct httpx.AsyncClient usage bypasses governance"
        )
        
        self._legacy_components["legacy_payload_loader"] = LegacyComponent(
            name="legacy_payload_loader",
            category=LegacyCategory.LEGACY_PAYLOAD.value,
            replacement="payload_loader",
            safe_to_remove=False,
            migration_coverage=100.0,
            deprecation_warning=None
        )
        
        self._legacy_components["fallback_execution"] = LegacyComponent(
            name="fallback_execution",
            category=LegacyCategory.COMPATIBILITY_BRIDGE.value,
            replacement="execution_controller",
            safe_to_remove=True,
            migration_coverage=85.0,
            deprecation_warning="Fallback execution paths should be removed after migration"
        )
        
        self._legacy_components["direct_request_bypass"] = LegacyComponent(
            name="direct_request_bypass",
            category=LegacyCategory.EXECUTION_REMNANT.value,
            replacement="execution_controller",
            safe_to_remove=False,
            migration_coverage=72.0,
            deprecation_warning="Direct request bypassing governance"
        )
        
        self._legacy_components["untracked_payload_execution"] = LegacyComponent(
            name="untracked_payload_execution",
            category=LegacyCategory.LEGACY_PAYLOAD.value,
            replacement="payload_loader",
            safe_to_remove=False,
            migration_coverage=95.0,
            deprecation_warning=None
        )
    
    def register_component_usage(self, component_name: str, file_path: str):
        if component_name in self._legacy_components:
            component = self._legacy_components[component_name]
            if file_path not in component.files_using:
                component.files_using.append(file_path)
            component.last_activity = datetime.now().isoformat()
            
            self._log_migration_event(
                event_type="component_usage",
                component=component_name,
                file=file_path
            )
    
    def get_component_status(self, component_name: str) -> Optional[Dict]:
        if component_name not in self._legacy_components:
            return None
        return self._legacy_components[component_name].to_dict()
    
    def get_all_components(self) -> Dict[str, Dict]:
        return {
            name: comp.to_dict()
            for name, comp in self._legacy_components.items()
        }
    
    def get_migration_summary(self) -> Dict:
        total = len(self._legacy_components)
        migrated = sum(1 for c in self._legacy_components.values() if c.status == ComponentStatus.MIGRATED.value)
        deprecated = sum(1 for c in self._legacy_components.values() if c.status == ComponentStatus.DEPRECATED.value)
        active = sum(1 for c in self._legacy_components.values() if c.status == ComponentStatus.ACTIVE.value)
        pending = sum(1 for c in self._legacy_components.values() if c.status == ComponentStatus.PENDING.value)
        
        avg_coverage = sum(c.migration_coverage for c in self._legacy_components.values()) / total if total else 0
        
        return {
            "total_components": total,
            "migrated": migrated,
            "deprecated": deprecated,
            "active": active,
            "pending": pending,
            "average_migration_coverage": round(avg_coverage, 2),
            "safe_to_remove_count": sum(1 for c in self._legacy_components.values() if c.safe_to_remove)
        }
    
    def _log_migration_event(self, event_type: str, component: str, file: str = "", details: str = ""):
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "component": component,
            "file": file,
            "details": details
        }
        self._migration_log.append(event)
        
        if len(self._migration_log) > self._max_log_entries:
            self._migration_log = self._migration_log[-self._max_log_entries:]
    
    def update_migration_coverage(self, component_name: str, coverage: float):
        if component_name in self._legacy_components:
            self._legacy_components[component_name].migration_coverage = coverage
            
            if coverage >= 95.0:
                self._legacy_components[component_name].status = ComponentStatus.MIGRATED.value
            elif coverage >= 70.0:
                self._legacy_components[component_name].status = ComponentStatus.DEPRECATED.value
            
            self._log_migration_event(
                event_type="migration_update",
                component=component_name,
                details=f"Coverage: {coverage}%"
            )
    
    def run_architecture_checks(self) -> List[ArchitectureCheck]:
        checks = []
        
        check = self._check_execution_governance()
        checks.append(check)
        
        check = self._check_payload_loader_usage()
        checks.append(check)
        
        check = self._check_module_router_integration()
        checks.append(check)
        
        check = self._check_mode_enforcement()
        checks.append(check)
        
        check = self._check_tracing_coverage()
        checks.append(check)
        
        self._integrity_checks = checks
        return checks
    
    def _check_execution_governance(self) -> ArchitectureCheck:
        check = ArchitectureCheck(name="execution_governance", timestamp=datetime.now().isoformat())
        
        issues = []
        warnings = []
        
        from modules.execution_controller import get_execution_controller
        try:
            ec = get_execution_controller()
            if ec is None:
                issues.append("Execution controller not initialized")
                check.passed = False
            else:
                stats = ec.get_execution_stats()
                if stats.get("total_requests", 0) == 0:
                    warnings.append("No requests through execution controller")
        except Exception as e:
            issues.append(f"Execution controller check failed: {e}")
            check.passed = False
        
        check.issues = issues
        check.warnings = warnings
        return check
    
    def _check_payload_loader_usage(self) -> ArchitectureCheck:
        check = ArchitectureCheck(name="payload_loader_usage", timestamp=datetime.now().isoformat())
        
        from modules.payload_loader import get_payload_loader
        try:
            loader = get_payload_loader()
            modules = loader.list_modules()
            
            if not modules:
                check.warnings.append("No payload modules loaded")
            else:
                for module in modules:
                    info = loader.get_module_info(module)
                    if info.get("total", 0) == 0:
                        check.warnings.append(f"Module {module} has no payloads")
        except Exception as e:
            check.issues.append(f"Payload loader check failed: {e}")
            check.passed = False
        
        return check
    
    def _check_module_router_integration(self) -> ArchitectureCheck:
        check = ArchitectureCheck(name="module_router_integration", timestamp=datetime.now().isoformat())
        
        from modules.module_router import get_module_router
        try:
            router = get_module_router()
            modules = router.list_available_modules()
            
            if not modules:
                check.warnings.append("No modules registered")
            else:
                enabled = router.list_enabled_modules()
                if len(enabled) == 0:
                    check.warnings.append("No modules enabled")
        except Exception as e:
            check.issues.append(f"Module router check failed: {e}")
            check.passed = False
        
        return check
    
    def _check_mode_enforcement(self) -> ArchitectureCheck:
        check = ArchitectureCheck(name="mode_enforcement", timestamp=datetime.now().isoformat())
        
        from modules.mode_manager import get_mode_manager
        try:
            manager = get_mode_manager()
            mode = manager.get_current_mode()
            
            if not mode:
                check.warnings.append("No execution mode set")
        except Exception as e:
            check.issues.append(f"Mode manager check failed: {e}")
            check.passed = False
        
        return check
    
    def _check_tracing_coverage(self) -> ArchitectureCheck:
        check = ArchitectureCheck(name="tracing_coverage", timestamp=datetime.now().isoformat())
        
        from modules.logger_manager import get_logger_manager
        try:
            manager = get_logger_manager()
            summary = manager.get_events_summary()
            
            if summary.get("total", 0) == 0:
                check.warnings.append("No events logged - tracing may not be active")
        except Exception as e:
            check.warnings.append(f"Tracing check warning: {e}")
        
        return check
    
    def get_integrity_report(self) -> Dict:
        if not self._integrity_checks:
            self.run_architecture_checks()
        
        passed = sum(1 for c in self._integrity_checks if c.passed)
        failed = len(self._integrity_checks) - passed
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total_checks": len(self._integrity_checks),
            "passed": passed,
            "failed": failed,
            "checks": [c.to_dict() for c in self._integrity_checks]
        }
    
    def get_removable_components(self) -> List[Dict]:
        removable = []
        
        for name, comp in self._legacy_components.items():
            if comp.safe_to_remove and comp.migration_coverage >= 95.0:
                removable.append(comp.to_dict())
        
        return removable
    
    def get_migration_analytics(self) -> Dict:
        if not self._migration_log:
            return {"total_events": 0}
        
        event_types = {}
        components = set()
        
        for event in self._migration_log:
            event_types[event["event_type"]] = event_types.get(event["event_type"], 0) + 1
            components.add(event.get("component", ""))
        
        return {
            "total_events": len(self._migration_log),
            "event_types": event_types,
            "components_tracked": len(components)
        }
    
    def log_legacy_usage(self, component_name: str, file_path: str, reason: str = ""):
        if component_name in self._legacy_components:
            self.register_component_usage(component_name, file_path)
    
    def get_cleanup_recommendations(self) -> List[str]:
        recommendations = []
        
        for name, comp in self._legacy_components.items():
            if comp.safe_to_remove and comp.migration_coverage >= 95.0:
                recommendations.append(f"SAFE: Remove {name} - {comp.migration_coverage}% coverage")
            elif comp.migration_coverage >= 70.0:
                recommendations.append(f"SOON: Deprecate {name} - {comp.migration_coverage}% coverage")
            elif comp.migration_coverage < 50.0:
                recommendations.append(f"ATTENTION: {name} only {comp.migration_coverage}% migrated")
        
        return recommendations


_cleanup_instance: Optional[LegacyCleanupManager] = None


def get_legacy_cleanup_manager(config: Optional[Dict] = None) -> LegacyCleanupManager:
    global _cleanup_instance
    
    if _cleanup_instance is None:
        _cleanup_instance = LegacyCleanupManager(config)
    
    return _cleanup_instance


def reset_legacy_cleanup_manager():
    global _cleanup_instance
    _cleanup_instance = None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("\n=== Legacy Cleanup Manager ===\n")
    
    manager = get_legacy_cleanup_manager()
    
    print("=== Migration Summary ===")
    summary = manager.get_migration_summary()
    print(f"Total components: {summary['total_components']}")
    print(f"Migrated: {summary['migrated']}")
    print(f"Deprecated: {summary['deprecated']}")
    print(f"Active: {summary['active']}")
    print(f"Average coverage: {summary['average_migration_coverage']}%")
    
    print("\n=== Architecture Integrity ===")
    for check in manager.run_architecture_checks():
        status = "PASS" if check.passed else "FAIL"
        print(f"  {check.name}: {status}")
        for issue in check.issues:
            print(f"    - Issue: {issue}")
        for warning in check.warnings:
            print(f"    - Warning: {warning}")
    
    print("\n=== Cleanup Recommendations ===")
    for rec in manager.get_cleanup_recommendations():
        print(f"  {rec}")
    
    print("\n=== Removable Components ===")
    removable = manager.get_removable_components()
    print(f"  {len(removable)} components safe to remove")