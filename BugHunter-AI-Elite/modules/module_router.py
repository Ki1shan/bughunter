"""
BugHunter AI Elite - Module Router
Centralized module execution routing and governance system.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class ModuleCategory(Enum):
    CLIENT_SIDE = "client-side"
    SERVER_SIDE = "server-side"
    AUTH = "auth"
    RECON = "recon"
    INJECTION = "injection"
    DATA_ACCESS = "data-access"
    API = "api"
    SESSION = "session"
    INFORMATION = "information"


class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DANGEROUS = "dangerous"


class ExecutionMode(Enum):
    BB_MODE = "bb_mode"
    AGGRESSIVE = "aggressive"
    LAB_MODE = "lab_mode"


@dataclass
class ModuleMetadata:
    module: str
    category: str
    risk_level: str = "medium"
    supports_auth: bool = False
    supports_rag_guidance: bool = True
    requires_network: bool = True
    requires_payloads: bool = True
    supports_safe_mode: bool = True
    supports_aggressive_mode: bool = True
    supports_lab_mode: bool = True
    execution_priority: int = 5
    description: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "module": self.module,
            "category": self.category,
            "risk_level": self.risk_level,
            "supports_auth": self.supports_auth,
            "supports_rag_guidance": self.supports_rag_guidance,
            "requires_network": self.requires_network,
            "requires_payloads": self.requires_payloads,
            "supports_safe_mode": self.supports_safe_mode,
            "supports_aggressive_mode": self.supports_aggressive_mode,
            "supports_lab_mode": self.supports_lab_mode,
            "execution_priority": self.execution_priority,
            "description": self.description,
        }


@dataclass
class ModuleConfig:
    enabled: bool = True
    safe: bool = True
    requires_auth: bool = False
    supports_bb_mode: bool = True
    supports_aggressive: bool = True
    supports_lab: bool = True
    max_concurrent: int = 10
    timeout: int = 30
    retry_on_fail: bool = True
    
    def to_dict(self) -> Dict:
        return {
            "enabled": self.enabled,
            "safe": self.safe,
            "requires_auth": self.requires_auth,
            "supports_bb_mode": self.supports_bb_mode,
            "supports_aggressive": self.supports_aggressive,
            "supports_lab": self.supports_lab,
            "max_concurrent": self.max_concurrent,
            "timeout": self.timeout,
            "retry_on_fail": self.retry_on_fail,
        }


@dataclass
class ModuleRegistration:
    name: str
    metadata: ModuleMetadata
    config: ModuleConfig
    handler: Optional[Callable] = None
    dependencies: List[str] = field(default_factory=list)
    loaded: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "metadata": self.metadata.to_dict(),
            "config": self.config.to_dict(),
            "dependencies": self.dependencies,
            "loaded": self.loaded,
        }


class ModuleRouter:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._modules: Dict[str, ModuleRegistration] = {}
        self._execution_mode = ExecutionMode.BB_MODE
        self._execution_order: List[str] = []
        self._initialized = False
    
    def register_module(
        self,
        name: str,
        metadata: ModuleMetadata,
        config: Optional[ModuleConfig] = None,
        dependencies: Optional[List[str]] = None,
        handler: Optional[Callable] = None
    ) -> ModuleRegistration:
        if config is None:
            config = ModuleConfig()
        
        if dependencies is None:
            dependencies = []
        
        registration = ModuleRegistration(
            name=name,
            metadata=metadata,
            config=config,
            dependencies=dependencies,
            handler=handler,
            loaded=True
        )
        
        self._modules[name] = registration
        
        if name not in self._execution_order:
            self._execution_order.append(name)
        
        logger.info(f"Registered module: {name}")
        
        return registration
    
    def unregister_module(self, name: str) -> bool:
        if name in self._modules:
            del self._modules[name]
            if name in self._execution_order:
                self._execution_order.remove(name)
            logger.info(f"Unregistered module: {name}")
            return True
        return False
    
    def get_module(self, name: str) -> Optional[ModuleRegistration]:
        return self._modules.get(name)
    
    def get_all_modules(self) -> Dict[str, ModuleRegistration]:
        return self._modules.copy()
    
    def list_enabled_modules(self) -> List[str]:
        enabled = []
        for name, reg in self._modules.items():
            if reg.config.enabled:
                enabled.append(name)
        return enabled
    
    def list_available_modules(self) -> List[str]:
        return list(self._modules.keys())
    
    def is_module_enabled(self, name: str) -> bool:
        if name not in self._modules:
            return False
        return self._modules[name].config.enabled
    
    def enable_module(self, name: str) -> bool:
        if name in self._modules:
            self._modules[name].config.enabled = True
            return True
        return False
    
    def disable_module(self, name: str) -> bool:
        if name in self._modules:
            self._modules[name].config.enabled = False
            return True
        return False
    
    def set_execution_mode(self, mode: ExecutionMode):
        self._execution_mode = mode
        logger.info(f"Execution mode set to: {mode.value}")
    
    def get_execution_mode(self) -> ExecutionMode:
        return self._execution_mode
    
    def check_execution_eligibility(
        self,
        module_name: str,
        context: Optional[Dict] = None
    ) -> tuple[bool, str]:
        context = context or {}
        
        if module_name not in self._modules:
            return False, f"Module '{module_name}' not registered"
        
        module = self._modules[module_name]
        
        if not module.config.enabled:
            return False, f"Module '{module_name}' is disabled"
        
        mode = self._execution_mode
        
        if mode == ExecutionMode.BB_MODE:
            if not module.config.supports_bb_mode:
                return False, f"Module '{module_name}' does not support bb_mode"
            if not module.config.safe:
                return False, f"Module '{module_name}' is not safe for bb_mode"
        
        elif mode == ExecutionMode.AGGRESSIVE:
            if not module.config.supports_aggressive:
                return False, f"Module '{module_name}' does not support aggressive mode"
        
        elif mode == ExecutionMode.LAB_MODE:
            if not module.config.supports_lab:
                return False, f"Module '{module_name}' does not support lab_mode"
        
        has_auth = context.get("has_auth", False)
        if module.config.requires_auth and not has_auth:
            return False, f"Module '{module_name}' requires authentication"
        
        return True, "eligible"
    
    def check_dependencies(
        self,
        module_name: str,
        available_modules: Optional[Set[str]] = None
    ) -> tuple[bool, List[str]]:
        if module_name not in self._modules:
            return False, []
        
        module = self._modules[module_name]
        
        if not module.dependencies:
            return True, []
        
        available = available_modules or set()
        missing = []
        
        for dep in module.dependencies:
            if dep not in self._modules:
                missing.append(dep)
            elif not self.is_module_enabled(dep):
                if dep not in available:
                    missing.append(dep)
        
        return len(missing) == 0, missing
    
    def resolve_dependencies(
        self,
        module_names: List[str],
        available_modules: Optional[Set[str]] = None
    ) -> List[str]:
        available = available_modules or set(self._modules.keys())
        
        resolved = []
        visited = set()
        queue = list(module_names)
        
        while queue:
            module_name = queue.pop(0)
            
            if module_name in visited:
                continue
            
            visited.add(module_name)
            
            if module_name not in self._modules:
                continue
            
            module = self._modules[module_name]
            
            for dep in module.dependencies:
                if dep not in visited and dep not in resolved:
                    if dep in self._modules and self.is_module_enabled(dep):
                        queue.append(dep)
            
            if module_name not in resolved and self.is_module_enabled(module_name):
                resolved.append(module_name)
        
        return resolved
    
    def get_module_execution_order(
        self,
        module_names: Optional[List[str]] = None,
        category: Optional[str] = None
    ) -> List[str]:
        if module_names:
            modules = module_names
        else:
            modules = self.list_enabled_modules()
        
        if category:
            modules = [
                m for m in modules
                if m in self._modules and self._modules[m].metadata.category == category
            ]
        
        sorted_modules = []
        for name in modules:
            if name in self._modules:
                sorted_modules.append((name, self._modules[name].metadata.execution_priority))
        
        sorted_modules.sort(key=lambda x: x[1])
        return [m[0] for m in sorted_modules]
    
    async def execute_module(
        self,
        module_name: str,
        target: Any,
        context: Optional[Dict] = None,
        **kwargs
    ) -> Dict:
        context = context or {}
        
        eligible, reason = self.check_execution_eligibility(module_name, context)
        
        if not eligible:
            return {
                "module": module_name,
                "success": False,
                "error": reason,
                "results": []
            }
        
        if module_name not in self._modules:
            return {
                "module": module_name,
                "success": False,
                "error": f"Module '{module_name}' not found",
                "results": []
            }
        
        module = self._modules[module_name]
        handler = module.handler
        
        if handler is None:
            return {
                "module": module_name,
                "success": False,
                "error": f"No handler for module '{module_name}'",
                "results": []
            }
        
        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(target, context, **kwargs)
            else:
                result = handler(target, context, **kwargs)
            
            return {
                "module": module_name,
                "success": True,
                "results": result
            }
            
        except Exception as e:
            logger.error(f"Module execution error for {module_name}: {e}")
            return {
                "module": module_name,
                "success": False,
                "error": str(e),
                "results": []
            }
    
    async def execute_multiple(
        self,
        module_names: List[str],
        target: Any,
        context: Optional[Dict] = None,
        **kwargs
    ) -> Dict:
        context = context or {}
        
        resolved_modules = self.resolve_dependencies(
            module_names,
            context.get("available_modules")
        )
        
        results = []
        
        for module_name in resolved_modules:
            if module_name in self._modules and self.is_module_enabled(module_name):
                result = await self.execute_module(module_name, target, context, **kwargs)
                results.append(result)
        
        return {
            "modules_executed": len(results),
            "results": results
        }
    
    def get_module_info(self, module_name: str) -> Optional[Dict]:
        if module_name not in self._modules:
            return None
        
        module = self._modules[module_name]
        return module.to_dict()
    
    def get_all_module_info(self) -> Dict[str, Dict]:
        return {
            name: reg.to_dict()
            for name, reg in self._modules.items()
        }
    
    def update_module_config(self, module_name: str, config: Dict) -> bool:
        if module_name not in self._modules:
            return False
        
        module = self._modules[module_name]
        
        if "enabled" in config:
            module.config.enabled = config["enabled"]
        if "safe" in config:
            module.config.safe = config["safe"]
        if "requires_auth" in config:
            module.config.requires_auth = config["requires_auth"]
        if "supports_bb_mode" in config:
            module.config.supports_bb_mode = config["supports_bb_mode"]
        if "max_concurrent" in config:
            module.config.max_concurrent = config["max_concurrent"]
        if "timeout" in config:
            module.config.timeout = config["timeout"]
        
        return True
    
    def get_modules_by_category(self, category: str) -> List[str]:
        modules = []
        for name, reg in self._modules.items():
            if reg.metadata.category == category:
                modules.append(name)
        return modules
    
    def get_modules_by_risk(self, risk_level: str) -> List[str]:
        modules = []
        for name, reg in self._modules.items():
            if reg.metadata.risk_level == risk_level:
                modules.append(name)
        return modules
    
    def get_router_status(self) -> Dict:
        return {
            "total_modules": len(self._modules),
            "enabled_modules": len(self.list_enabled_modules()),
            "execution_mode": self._execution_mode.value,
            "execution_order": self._execution_order,
            "categories": list(set(
                reg.metadata.category
                for reg in self._modules.values()
            ))
        }


def create_default_router(config: Optional[Dict] = None) -> ModuleRouter:
    router = ModuleRouter(config)
    
    router.register_module(
        name="xss",
        metadata=ModuleMetadata(
            module="xss",
            category=ModuleCategory.CLIENT_SIDE.value,
            risk_level=RiskLevel.MEDIUM.value,
            supports_auth=True,
            requires_payloads=True,
            execution_priority=3,
            description="Cross-Site Scripting detection"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=True,
            requires_auth=False,
            supports_bb_mode=True
        )
    )
    
    router.register_module(
        name="sqli",
        metadata=ModuleMetadata(
            module="sqli",
            category=ModuleCategory.INJECTION.value,
            risk_level=RiskLevel.HIGH.value,
            supports_auth=False,
            requires_payloads=True,
            execution_priority=2,
            description="SQL Injection detection"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=False,
            requires_auth=False,
            supports_bb_mode=True
        ),
        dependencies=["attack_surface"]
    )
    
    router.register_module(
        name="ssrf",
        metadata=ModuleMetadata(
            module="ssrf",
            category=ModuleCategory.INJECTION.value,
            risk_level=RiskLevel.HIGH.value,
            supports_auth=False,
            requires_payloads=True,
            execution_priority=4,
            description="Server-Side Request Forgery detection"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=False,
            requires_auth=False,
            supports_bb_mode=True
        )
    )
    
    router.register_module(
        name="xxe",
        metadata=ModuleMetadata(
            module="xxe",
            category=ModuleCategory.INJECTION.value,
            risk_level=RiskLevel.HIGH.value,
            supports_auth=False,
            requires_payloads=True,
            execution_priority=5,
            description="XML External Entity detection"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=False,
            requires_auth=False,
            supports_bb_mode=True
        )
    )
    
    router.register_module(
        name="ssti",
        metadata=ModuleMetadata(
            module="ssti",
            category=ModuleCategory.INJECTION.value,
            risk_level=RiskLevel.HIGH.value,
            supports_auth=False,
            requires_payloads=True,
            execution_priority=4,
            description="Server-Side Template Injection detection"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=False,
            requires_auth=False,
            supports_bb_mode=True
        )
    )
    
    router.register_module(
        name="jwt",
        metadata=ModuleMetadata(
            module="jwt",
            category=ModuleCategory.SESSION.value,
            risk_level=RiskLevel.MEDIUM.value,
            supports_auth=True,
            requires_payloads=True,
            execution_priority=6,
            description="JWT vulnerabilities detection"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=True,
            requires_auth=False,
            supports_bb_mode=True
        )
    )
    
    router.register_module(
        name="idor",
        metadata=ModuleMetadata(
            module="idor",
            category=ModuleCategory.DATA_ACCESS.value,
            risk_level=RiskLevel.MEDIUM.value,
            supports_auth=True,
            requires_payloads=False,
            execution_priority=3,
            description="Insecure Direct Object Reference detection"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=True,
            requires_auth=True,
            supports_bb_mode=True
        ),
        dependencies=["auth_simulation"]
    )
    
    router.register_module(
        name="crawler",
        metadata=ModuleMetadata(
            module="crawler",
            category=ModuleCategory.RECON.value,
            risk_level=RiskLevel.SAFE.value,
            supports_auth=False,
            requires_network=True,
            requires_payloads=False,
            execution_priority=1,
            description="Web crawler for endpoint discovery"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=True,
            requires_auth=False,
            supports_bb_mode=True
        )
    )
    
    router.register_module(
        name="attack_surface",
        metadata=ModuleMetadata(
            module="attack_surface",
            category=ModuleCategory.RECON.value,
            risk_level=RiskLevel.SAFE.value,
            supports_auth=False,
            requires_network=True,
            requires_payloads=False,
            execution_priority=1,
            description="Attack surface expansion and discovery"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=True,
            requires_auth=False,
            supports_bb_mode=True
        ),
        dependencies=["crawler"]
    )
    
    router.register_module(
        name="auth_simulation",
        metadata=ModuleMetadata(
            module="auth_simulation",
            category=ModuleCategory.AUTH.value,
            risk_level=RiskLevel.MEDIUM.value,
            supports_auth=True,
            requires_network=True,
            requires_payloads=False,
            execution_priority=2,
            description="Multi-user authentication simulation"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=True,
            requires_auth=False,
            supports_bb_mode=True
        )
    )
    
    router.register_module(
        name="heuristic",
        metadata=ModuleMetadata(
            module="heuristic",
            category=ModuleCategory.INFORMATION.value,
            risk_level=RiskLevel.LOW.value,
            supports_auth=False,
            requires_network=True,
            requires_payloads=False,
            execution_priority=4,
            description="Heuristic analysis and anomaly detection"
        ),
        config=ModuleConfig(
            enabled=True,
            safe=True,
            requires_auth=False,
            supports_bb_mode=True
        )
    )
    
    return router


_router_instance: Optional[ModuleRouter] = None


def get_module_router(config: Optional[Dict] = None) -> ModuleRouter:
    global _router_instance
    
    if _router_instance is None:
        _router_instance = create_default_router(config)
    
    return _router_instance


def reset_module_router():
    global _router_instance
    _router_instance = None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    router = create_default_router()
    
    print("\n=== Module Router Status ===\n")
    
    status = router.get_router_status()
    print(f"Total modules: {status['total_modules']}")
    print(f"Enabled: {status['enabled_modules']}")
    print(f"Mode: {status['execution_mode']}")
    
    print("\n=== Enabled Modules ===")
    for module in router.list_enabled_modules():
        info = router.get_module_info(module)
        print(f"  {module}: {info['metadata']['description']}")
    
    print("\n=== Dependencies ===")
    for module in router.list_available_modules():
        deps = router.get_module(module).dependencies
        if deps:
            print(f"  {module} -> {deps}")