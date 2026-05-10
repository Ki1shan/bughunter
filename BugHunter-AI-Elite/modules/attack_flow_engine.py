"""
Attack Flow Engine - Adaptive step-by-step vulnerability exploitation orchestration.

Executes vulnerability tests in sequence, adapts strategy based on results,
and escalates through exploitation stages using RAG decision rules.

DOES NOT modify RAG files, payloads, or existing modules.
Adds a new orchestration layer only.
"""

import asyncio
import logging
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("BugHunter")

try:
    from modules.payload_loader import get_payload_loader
    _HAS_LOADER = True
except ImportError:
    _HAS_LOADER = False


class FlowStepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ESCALATING = "escalating"


class FlowResult(Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    SUSPECTED = "suspected"
    REJECTED = "rejected"
    EXHAUSTED = "exhausted"
    TIMEOUT = "timeout"


@dataclass
class FlowStep:
    name: str
    technique: str
    payload: str
    payload_category: str
    expected_indicators: list = field(default_factory=list)
    priority: int = 1
    status: FlowStepStatus = FlowStepStatus.PENDING
    validation_result: dict = None
    attempt: int = 0


@dataclass
class FlowState:
    vuln_type: str
    endpoint: str
    param: str
    baseline_response: dict
    steps: list = field(default_factory=list)
    current_step_index: int = 0
    result: FlowResult = FlowResult.SUSPECTED
    confidence: float = 0.0
    confirmed_findings: list = field(default_factory=list)
    escalation_stage: int = 0
    max_steps: int = 8
    max_escalation_stages: int = 3
    stop_reason: str = ""
    step_log: list = field(default_factory=list)
    consecutive_failures: int = 0


ESCALATION_CHAINS = {
    "sqli": [
        {
            "stage": 0,
            "name": "error_based_probe",
            "description": "Test for SQL error messages",
            "techniques": ["error_based"],
            "payload_categories": ["error_based"],
            "confirm_on": ["strong_pattern", "sql_error"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "union_based",
            "description": "UNION-based injection",
            "techniques": ["union_based"],
            "payload_categories": ["error_based"],
            "confirm_on": ["strong_pattern", "union_result"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "blind_probe",
            "description": "Boolean/time-based blind SQLi",
            "techniques": ["blind_boolean", "time_based"],
            "payload_categories": ["blind"],
            "confirm_on": ["strong_pattern", "content_change", "time_delay"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "data_extraction",
            "description": "Extract database version/user info",
            "techniques": ["data_extract"],
            "payload_categories": ["error_based", "union_based"],
            "confirm_on": ["strong_pattern", "data_leak"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "xss": [
        {
            "stage": 0,
            "name": "reflection_probe",
            "description": "Test if payload reflects in response",
            "techniques": ["reflected"],
            "payload_categories": ["basic"],
            "confirm_on": ["strong_pattern", "payload_reflected"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "context_breakout",
            "description": "Break out of HTML/JS context",
            "techniques": ["context_breakout"],
            "payload_categories": ["basic", "filter_bypass"],
            "confirm_on": ["strong_pattern", "script_execution"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "filter_bypass",
            "description": "Bypass WAF/filters with encoding",
            "techniques": ["filter_bypass"],
            "payload_categories": ["filter_bypass", "encoding_variations"],
            "confirm_on": ["strong_pattern", "payload_reflected"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "dom_sink_probe",
            "description": "Test for DOM-based XSS sinks",
            "techniques": ["dom_based"],
            "payload_categories": ["basic"],
            "confirm_on": ["strong_pattern", "dom_sink"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "ssrf": [
        {
            "stage": 0,
            "name": "internal_probe",
            "description": "Test internal IP access",
            "techniques": ["internal_network"],
            "payload_categories": ["internal_network"],
            "confirm_on": ["strong_pattern", "internal_response"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "bypass_probe",
            "description": "Bypass SSRF filters",
            "techniques": ["bypass"],
            "payload_categories": ["bypass_techniques"],
            "confirm_on": ["strong_pattern", "internal_response"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "cloud_metadata",
            "description": "Access cloud metadata endpoints",
            "techniques": ["cloud_metadata"],
            "payload_categories": ["internal_aws"],
            "confirm_on": ["strong_pattern", "metadata_response"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "blind_ssrf",
            "description": "Blind SSRF via OOB callback",
            "techniques": ["blind"],
            "payload_categories": ["internal_network"],
            "confirm_on": ["strong_pattern", "oob_callback"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "xxe": [
        {
            "stage": 0,
            "name": "entity_probe",
            "description": "Test basic XXE entity injection",
            "techniques": ["entity_injection"],
            "payload_categories": ["basic"],
            "confirm_on": ["strong_pattern", "entity_expansion"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "file_read",
            "description": "Read local files via XXE",
            "techniques": ["file_read"],
            "payload_categories": ["file_access"],
            "confirm_on": ["strong_pattern", "file_content"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "blind_xxe",
            "description": "Blind XXE via external DTD",
            "techniques": ["blind"],
            "payload_categories": ["blind"],
            "confirm_on": ["strong_pattern", "oob_callback"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "ssrf_via_xxe",
            "description": "SSRF via XXE external entity",
            "techniques": ["ssrf_via_xxe"],
            "payload_categories": ["ssrf"],
            "confirm_on": ["strong_pattern", "internal_response"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "ssti": [
        {
            "stage": 0,
            "name": "arithmetic_probe",
            "description": "Test arithmetic template evaluation",
            "techniques": ["arithmetic"],
            "payload_categories": ["basic"],
            "confirm_on": ["strong_pattern", "arithmetic_result"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "engine_detection",
            "description": "Identify template engine",
            "techniques": ["engine_detect"],
            "payload_categories": ["basic"],
            "confirm_on": ["strong_pattern", "engine_specific"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "rce_probe",
            "description": "Test for remote code execution",
            "techniques": ["rce"],
            "payload_categories": ["advanced"],
            "confirm_on": ["strong_pattern", "command_output"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "sandbox_escape",
            "description": "Escape template sandbox",
            "techniques": ["sandbox_escape"],
            "payload_categories": ["advanced"],
            "confirm_on": ["strong_pattern", "os_access"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "command_injection": [
        {
            "stage": 0,
            "name": "basic_probe",
            "description": "Test basic command injection",
            "techniques": ["basic"],
            "payload_categories": ["unix", "windows"],
            "confirm_on": ["strong_pattern", "command_output"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "blind_probe",
            "description": "Blind command injection via sleep/delay",
            "techniques": ["blind"],
            "payload_categories": ["unix", "windows"],
            "confirm_on": ["strong_pattern", "time_delay"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "filter_bypass",
            "description": "Bypass command filters",
            "techniques": ["filter_bypass"],
            "payload_categories": ["unix", "windows"],
            "confirm_on": ["strong_pattern", "command_output"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "oob_exfil",
            "description": "Out-of-band data exfiltration",
            "techniques": ["oob"],
            "payload_categories": ["unix"],
            "confirm_on": ["strong_pattern", "oob_callback"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "path_traversal": [
        {
            "stage": 0,
            "name": "basic_probe",
            "description": "Test basic path traversal",
            "techniques": ["basic"],
            "payload_categories": ["basic", "linux", "windows"],
            "confirm_on": ["strong_pattern", "file_content"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "null_byte",
            "description": "Null byte injection",
            "techniques": ["null_byte"],
            "payload_categories": ["basic", "linux", "windows"],
            "confirm_on": ["strong_pattern", "file_content"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "encoding_bypass",
            "description": "URL/double encoding bypass",
            "techniques": ["encoding"],
            "payload_categories": ["basic", "linux", "windows"],
            "confirm_on": ["strong_pattern", "file_content"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "sensitive_files",
            "description": "Access sensitive system files",
            "techniques": ["sensitive"],
            "payload_categories": ["linux", "windows"],
            "confirm_on": ["strong_pattern", "file_content"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "deserialization": [
        {
            "stage": 0,
            "name": "probe",
            "description": "Test for deserialization markers",
            "techniques": ["probe"],
            "payload_categories": ["basic"],
            "confirm_on": ["strong_pattern", "deser_marker"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "gadget_probe",
            "description": "Test gadget chain execution",
            "techniques": ["gadget"],
            "payload_categories": ["advanced"],
            "confirm_on": ["strong_pattern", "gadget_exec"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "rce_probe",
            "description": "RCE via deserialization",
            "techniques": ["rce"],
            "payload_categories": ["advanced"],
            "confirm_on": ["strong_pattern", "command_output"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "blind_deser",
            "description": "Blind deserialization via OOB",
            "techniques": ["blind"],
            "payload_categories": ["advanced"],
            "confirm_on": ["strong_pattern", "oob_callback"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "open_redirect": [
        {
            "stage": 0,
            "name": "basic_probe",
            "description": "Test basic redirect",
            "techniques": ["basic"],
            "payload_categories": ["payloads"],
            "confirm_on": ["strong_pattern", "redirect"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "encoded_probe",
            "description": "Encoded redirect payloads",
            "techniques": ["encoded"],
            "payload_categories": ["payloads"],
            "confirm_on": ["strong_pattern", "redirect"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "double_encoded",
            "description": "Double encoding bypass",
            "techniques": ["double_encoded"],
            "payload_categories": ["payloads"],
            "confirm_on": ["strong_pattern", "redirect"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "protocol_bypass",
            "description": "Protocol-relative bypass",
            "techniques": ["protocol"],
            "payload_categories": ["payloads"],
            "confirm_on": ["strong_pattern", "redirect"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "csrf": [
        {
            "stage": 0,
            "name": "token_probe",
            "description": "Check for CSRF token presence",
            "techniques": ["token_check"],
            "payload_categories": ["basic"],
            "confirm_on": ["no_token", "weak_token"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "bypass_probe",
            "description": "Bypass CSRF protections",
            "techniques": ["bypass"],
            "payload_categories": ["basic"],
            "confirm_on": ["strong_pattern", "action_executed"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "same_site_bypass",
            "description": "SameSite cookie bypass",
            "techniques": ["samesite"],
            "payload_categories": ["basic"],
            "confirm_on": ["strong_pattern", "cookie_sent"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "preflight_bypass",
            "description": "CORS preflight bypass",
            "techniques": ["cors"],
            "payload_categories": ["basic"],
            "confirm_on": ["strong_pattern", "cors_header"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "idor": [
        {
            "stage": 0,
            "name": "enum_probe",
            "description": "Enumerate ID patterns",
            "techniques": ["enumeration"],
            "payload_categories": ["id_enumeration"],
            "confirm_on": ["valid_response", "data_change"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "horizontal_probe",
            "description": "Horizontal privilege escalation",
            "techniques": ["horizontal"],
            "payload_categories": ["id_enumeration"],
            "confirm_on": ["data_access", "owner_change"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "vertical_probe",
            "description": "Vertical privilege escalation",
            "techniques": ["vertical"],
            "payload_categories": ["id_enumeration"],
            "confirm_on": ["admin_access", "priv_change"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "uuid_probe",
            "description": "UUID/GUID enumeration",
            "techniques": ["uuid"],
            "payload_categories": ["id_enumeration"],
            "confirm_on": ["valid_response", "data_change"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "jwt": [
        {
            "stage": 0,
            "name": "decode_probe",
            "description": "Decode and analyze JWT structure",
            "techniques": ["decode"],
            "payload_categories": ["basic"],
            "confirm_on": ["weak_alg", "no_signature"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "alg_none",
            "description": "Algorithm none attack",
            "techniques": ["alg_none"],
            "payload_categories": ["advanced"],
            "confirm_on": ["accepted_token", "auth_bypass"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "key_probe",
            "description": "Weak key / brute force",
            "techniques": ["brute_force"],
            "payload_categories": ["advanced"],
            "confirm_on": ["key_found", "signed_token"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "claim_manipulation",
            "description": "Manipulate JWT claims",
            "techniques": ["claim_modify"],
            "payload_categories": ["advanced"],
            "confirm_on": ["priv_escalation", "role_change"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "graphql": [
        {
            "stage": 0,
            "name": "introspection",
            "description": "Schema introspection",
            "techniques": ["introspect"],
            "payload_categories": ["basic"],
            "confirm_on": ["schema_response", "type_info"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "batch_probe",
            "description": "Batch query attack",
            "techniques": ["batching"],
            "payload_categories": ["advanced"],
            "confirm_on": ["batch_response", "rate_bypass"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "injection_probe",
            "description": "GraphQL injection",
            "techniques": ["injection"],
            "payload_categories": ["advanced"],
            "confirm_on": ["strong_pattern", "data_leak"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "dos_probe",
            "description": "Deep nesting DoS",
            "techniques": ["dos"],
            "payload_categories": ["advanced"],
            "confirm_on": ["timeout", "error_response"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
    "race_conditions": [
        {
            "stage": 0,
            "name": "timing_probe",
            "description": "Measure baseline timing",
            "techniques": ["timing"],
            "payload_categories": ["basic"],
            "confirm_on": ["timing_variance", "inconsistent"],
            "next_stage_on_success": 1,
            "next_stage_on_weak": 1,
        },
        {
            "stage": 1,
            "name": "concurrent_probe",
            "description": "Concurrent request testing",
            "techniques": ["concurrent"],
            "payload_categories": ["techniques"],
            "confirm_on": ["race_detected", "state_change"],
            "next_stage_on_success": 2,
            "next_stage_on_weak": 2,
        },
        {
            "stage": 2,
            "name": "turbo_probe",
            "description": "HTTP/2 rapid reset attack",
            "techniques": ["turbo"],
            "payload_categories": ["techniques"],
            "confirm_on": ["race_detected", "state_change"],
            "next_stage_on_success": 3,
            "next_stage_on_weak": 3,
        },
        {
            "stage": 3,
            "name": "limit_bypass",
            "description": "Bypass rate/usage limits",
            "techniques": ["limit_bypass"],
            "payload_categories": ["techniques"],
            "confirm_on": ["limit_exceeded", "state_change"],
            "next_stage_on_success": -1,
            "next_stage_on_weak": -1,
        },
    ],
}

DEFAULT_ESCALATION_CHAIN = [
    {
        "stage": 0,
        "name": "basic_probe",
        "description": "Test basic vulnerability indicators",
        "techniques": ["basic"],
        "payload_categories": ["basic"],
        "confirm_on": ["strong_pattern", "payload_reflected"],
        "next_stage_on_success": 1,
        "next_stage_on_weak": 1,
    },
    {
        "stage": 1,
        "name": "advanced_probe",
        "description": "Test advanced techniques",
        "techniques": ["advanced"],
        "payload_categories": ["advanced"],
        "confirm_on": ["strong_pattern", "content_change"],
        "next_stage_on_success": 2,
        "next_stage_on_weak": 2,
    },
    {
        "stage": 2,
        "name": "bypass_probe",
        "description": "Bypass protections",
        "techniques": ["bypass"],
        "payload_categories": ["filter_bypass"],
        "confirm_on": ["strong_pattern", "payload_reflected"],
        "next_stage_on_success": 3,
        "next_stage_on_weak": 3,
    },
    {
        "stage": 3,
        "name": "final_probe",
        "description": "Final exploitation attempt",
        "techniques": ["final"],
        "payload_categories": ["advanced"],
        "confirm_on": ["strong_pattern"],
        "next_stage_on_success": -1,
        "next_stage_on_weak": -1,
    },
]


class AttackFlowEngine:
    """Adaptive step-by-step vulnerability exploitation orchestrator.

    Executes vulnerability tests sequentially, adapts strategy based on
    validation results, and escalates through exploitation stages using
    RAG decision rules and learning signals.
    """

    def __init__(self, config, rag_loader=None, validator=None, learning_system=None, adaptive_learning=None, perf_optimizer=None):
        self.config = config
        self.rag_loader = rag_loader
        self.validator = validator
        self.learning = learning_system
        self.adaptive = adaptive_learning
        self.perf = perf_optimizer
        self._payloads_cache = {}
        self._rag_configs = {}
        self._flow_log = []

    def _log(self, message: str):
        logger.info(f"[FLOW] {message}")
        self._flow_log.append(message)

    async def _load_payloads(self) -> dict:
        if "payloads" not in self._payloads_cache:
            try:
                import json
                import os
                payload_path = os.path.join(
                    os.path.dirname(os.path.dirname(__file__)),
                    "payloads.json"
                )
                with open(payload_path, "r", encoding="utf-8") as f:
                    self._payloads_cache["payloads"] = json.load(f)
            except Exception as e:
                self._log(f"Failed to load payloads: {e}")
                self._payloads_cache["payloads"] = {}
        return self._payloads_cache["payloads"]

    def _get_rag_config(self, vuln_type: str) -> dict:
        if vuln_type not in self._rag_configs and self.rag_loader:
            try:
                configs = {
                    "detection": self.rag_loader.get_detection_config(vuln_type),
                    "decision_rules": self.rag_loader.get_decision_rules(vuln_type),
                    "advanced": self.rag_loader.get_advanced_config(vuln_type),
                    "learning": self.rag_loader.get_learning_config(vuln_type),
                }
                self._rag_configs[vuln_type] = configs
            except Exception:
                self._rag_configs[vuln_type] = {}
        return self._rag_configs.get(vuln_type, {})

    def _get_escalation_chain(self, vuln_type: str) -> list:
        return ESCALATION_CHAINS.get(vuln_type, DEFAULT_ESCALATION_CHAIN)

    def _get_payloads_for_category(self, payloads_db: dict, vuln_type: str, category: str) -> list:
        type_mapping = {
            "sqli": "sql_injection",
            "xss": "xss",
            "ssrf": "ssrf",
            "xxe": "xxe",
            "ssti": "ssti",
            "command_injection": "command_injection",
            "path_traversal": "path_traversal",
            "deserialization": "deserialization",
            "open_redirect": "open_redirect",
            "csrf": "csrf",
            "idor": "fuzzing",
            "jwt": "jwt",
            "graphql": "graphql",
            "race_conditions": "race_conditions",
        }
        db_key = type_mapping.get(vuln_type, vuln_type)
        section = payloads_db.get(db_key, {})
        if isinstance(section, dict):
            result = []
            if category in section:
                cat_value = section[category]
                if isinstance(cat_value, list):
                    result.extend(cat_value)
                elif isinstance(cat_value, dict):
                    for sub_key, sub_val in cat_value.items():
                        if isinstance(sub_val, list):
                            result.extend(sub_val)
            if not result:
                for key, val in section.items():
                    if isinstance(val, list):
                        result.extend(val)
                    elif isinstance(val, dict):
                        for sub_key, sub_val in val.items():
                            if isinstance(sub_val, list):
                                result.extend(sub_val)
            return result[:4]
        elif isinstance(section, list):
            return section[:4]
        return []

    def _get_learned_payloads(self, vuln_type: str, endpoint_pattern: str) -> list:
        if self.learning:
            try:
                learned = self.learning.suggest_payloads_based_on_learned(
                    vuln_type, endpoint_pattern
                )
                if learned:
                    self._log(f"Using {len(learned)} learned payloads for {vuln_type}")
                    return learned
            except Exception:
                pass
        return []

    def _build_flow_steps(self, vuln_type: str, stage_config: dict, payloads: list, param: str) -> list:
        steps = []
        priority = 1
        for payload in payloads[:8]:
            if isinstance(payload, dict):
                payload_value = payload.get("value", payload.get("payload", str(payload)))
                payload_name = payload.get("name", "unknown")
            else:
                payload_value = str(payload)
                payload_name = "payload"
            step = FlowStep(
                name=f"{stage_config['name']}_{priority}",
                technique=stage_config["techniques"][0] if stage_config.get("techniques") else "basic",
                payload=payload_value,
                payload_category=stage_config["payload_categories"][0] if stage_config.get("payload_categories") else "basic",
                expected_indicators=stage_config.get("confirm_on", []),
                priority=priority,
            )
            steps.append(step)
            priority += 1
        return steps

    async def _execute_step(self, flow: FlowState, step: FlowStep, endpoint: str, param: str) -> dict:
        step.status = FlowStepStatus.RUNNING
        step.attempt += 1

        self._log(f"Testing step: {flow.vuln_type} -> {step.name} (attempt {step.attempt})")

        if not self.validator:
            self._log("No validator available, skipping step execution")
            step.status = FlowStepStatus.SKIPPED
            return {"confirmed": False, "confidence": "none", "reason": "no_validator"}

        try:
            from modules.execution_controller import get_execution_controller, ExecutionController

            baseline = flow.baseline_response
            baseline_text = baseline.get("text", "") if baseline else ""
            baseline_status = baseline.get("status_code", 200) if baseline else 200

            test_url = endpoint
            if param and step.payload:
                separator = "&" if "?" in test_url else "?"
                test_url = f"{test_url}{separator}{param}={step.payload}"

            metadata = {"module": "attack_flow", "vuln_type": flow.vuln_type, "payload_id": getattr(step, "payload_id", "")}
            
            exec_ctrl = get_execution_controller(self.config)
            response = await exec_ctrl.get(test_url, headers={"User-Agent": "BugHunter-AI-Flow/v2.0"}, metadata=metadata)
            
            if response and not response.error:
                payload_response = {
                    "text": response.body,
                    "status_code": response.status_code,
                    "length": len(response.body) if response.body else 0,
                }
            else:
                fallback = ExecutionController(self.config)
                response = await fallback.get(test_url, headers={"User-Agent": "BugHunter-AI-Flow/v2.0"}, metadata=metadata)
                await fallback.close()
                
                if response and not response.error:
                    payload_response = {
                        "text": response.body,
                        "status_code": response.status_code,
                        "length": len(response.body) if response.body else 0,
                    }
                else:
                    payload_response = {"text": "", "status_code": 0, "length": 0}

            validation = self.validator.validate_response(
                baseline_response={
                    "text": baseline_text,
                    "status_code": baseline_status,
                    "length": len(baseline_text) if baseline_text else 0,
                },
                payload_response=payload_response,
                vuln_type=flow.vuln_type,
                payload=step.payload,
            )

            step.validation_result = validation
            return validation

        except Exception as e:
            self._log(f"Step execution error: {e}")
            step.status = FlowStepStatus.FAILED
            return {"confirmed": False, "confidence": "none", "reason": str(e)}

    def _evaluate_step_result(self, validation: dict, step: FlowStep, flow: FlowState) -> FlowStepStatus:
        if validation.get("confirmed"):
            confidence = validation.get("confidence", "low")
            if confidence == "high":
                self._log(f"Success -> escalating: {step.name} (strong evidence)")
                return FlowStepStatus.SUCCESS
            elif confidence == "medium":
                self._log(f"Weak signal -> trying bypass: {step.name}")
                return FlowStepStatus.SUCCESS
            else:
                self._log(f"Low confidence -> continuing: {step.name}")
                return FlowStepStatus.SUCCESS
        elif validation.get("confidence") == "low" and validation.get("content_changed"):
            self._log(f"Weak signal -> trying advanced: {step.name}")
            return FlowStepStatus.SUCCESS
        else:
            self._log(f"Failed -> trying next technique: {step.name}")
            return FlowStepStatus.FAILED

    def _should_escalate(self, flow: FlowState) -> bool:
        if flow.escalation_stage >= flow.max_escalation_stages:
            return False
        confirmed_count = len(flow.confirmed_findings)
        if confirmed_count > 0 and flow.escalation_stage >= 1:
            chain = self._get_escalation_chain(flow.vuln_type)
            if flow.escalation_stage < len(chain):
                return True
        return flow.confidence >= 0.3 and flow.escalation_stage < flow.max_escalation_stages

    def _should_stop(self, flow: FlowState) -> bool:
        if flow.stop_reason:
            return True
        total_steps = sum(len(s) for s in [flow.steps] if flow.steps)
        if total_steps >= flow.max_steps:
            flow.stop_reason = "max_steps_reached"
            return True
        if flow.confidence < 0.05 and len(flow.confirmed_findings) == 0 and flow.current_step_index >= 4:
            flow.stop_reason = "confidence_below_threshold"
            return True
        if flow.result == FlowResult.CONFIRMED and not self._should_escalate(flow):
            flow.stop_reason = "confirmed_and_escalation_complete"
            return True
        return False

    def _update_confidence(self, flow: FlowState, validation: dict):
        if validation.get("confirmed"):
            confidence_map = {"high": 0.95, "medium": 0.7, "low": 0.4}
            new_conf = confidence_map.get(validation.get("confidence", "low"), 0.3)
            flow.confidence = max(flow.confidence, new_conf)
            if validation.get("confidence") == "high":
                flow.result = FlowResult.CONFIRMED
            elif validation.get("confidence") == "medium":
                if flow.result != FlowResult.CONFIRMED:
                    flow.result = FlowResult.LIKELY
            else:
                if flow.result not in (FlowResult.CONFIRMED, FlowResult.LIKELY):
                    flow.result = FlowResult.SUSPECTED
        elif validation.get("content_changed"):
            flow.confidence = max(flow.confidence, 0.2)
            if flow.result == FlowResult.SUSPECTED:
                pass
        else:
            flow.confidence = max(flow.confidence * 0.9, 0.0)

        if self.adaptive:
            flow.confidence = self.adaptive.adjust_confidence(
                flow.vuln_type,
                flow.endpoint,
                flow.confidence,
                flow.step_log,
                consecutive_failures=0,
                consecutive_successes=len(flow.confirmed_findings),
            )

    def get_adaptive_vuln_order(self, endpoint: str) -> list:
        """Get vuln type order from adaptive learning (module reordering before flow)."""
        if self.adaptive:
            return self.adaptive.suggest_vuln_order(endpoint)
        return []

    async def _run_escalation_stage(self, flow: FlowState, endpoint: str, param: str, stage_config: dict) -> bool:
        payloads = await self._load_payloads()

        categories = stage_config.get("payload_categories", ["basic"])
        stage_payloads = []
        for category in categories:
            category_payloads = self._get_payloads_for_category(payloads, flow.vuln_type, category)
            stage_payloads.extend(category_payloads)

        if self.adaptive:
            stage_payloads = self.adaptive.prioritize_payloads(flow.vuln_type, endpoint, stage_payloads)

        if self.perf:
            stage_payloads = self.perf.prioritize_payloads(stage_payloads, flow.vuln_type, endpoint)
            limit = self.perf.get_adaptive_limit(flow.vuln_type, stage_config["stage"])
            stage_payloads = stage_payloads[:limit]

        if not stage_payloads:
            self._log(f"No payloads for stage {stage_config['name']}, using fallback")
            
            fallback_map = {
                "sqli": "sql-injection",
                "xss": "xss",
                "ssrf": "ssrf-payloads",
                "ssti": "ssti",
                "xxe": "xxe",
                "command_injection": "command-injection",
            }
            
            module = fallback_map.get(flow.vuln_type, flow.vuln_type)
            
            if _HAS_LOADER:
                try:
                    loader = get_payload_loader()
                    vals = loader.get_payload_values(module, level="basic", limit=5)
                    stage_payloads = [{"value": v, "name": f"{module}_fallback_{i}"} for i, v in enumerate(vals)]
                except Exception:
                    stage_payloads = []
            
            if not stage_payloads:
                stage_payloads = [
                    {"value": "' OR '1'='1", "name": "dynamic_sqli_fallback", "payload_id": "fall_sqli_001"},
                ]
                
                if _HAS_LOADER:
                    try:
                        loader = get_payload_loader()
                        xss_vals = loader.get_payload_values("xss", level="basic", limit=2)
                        for i, v in enumerate(xss_vals):
                            stage_payloads.append({
                                "value": v,
                                "name": f"dynamic_xss_fallback_{i}",
                                "payload_id": f"fall_xss_{i:03d}"
                            })
                    except Exception:
                        pass

        steps = self._build_flow_steps(flow.vuln_type, stage_config, stage_payloads, param)
        flow.steps = steps

        stage_confirmed = False
        for i, step in enumerate(steps):
            if self._should_stop(flow):
                break

            if self.adaptive and self.adaptive.should_skip_payload(flow.vuln_type, endpoint, step.payload):
                step.status = FlowStepStatus.SKIPPED
                self._log(f"Skipping {step.name}: adaptive learning says skip")
                continue

            if self.perf and self.perf.should_prune_payload(flow.vuln_type, step.name, endpoint):
                step.status = FlowStepStatus.SKIPPED
                self._log(f"Skipping {step.name}: performance optimizer says skip")
                continue

            validation = await self._execute_step(flow, step, endpoint, param)
            status = self._evaluate_step_result(validation, step, flow)
            step.status = status

            if self.perf:
                resp_time = validation.get("response_time", 0)
                self.perf.record_request_time(endpoint, resp_time)
                self.perf.record_payload_result(flow.vuln_type, step.name, validation.get("confirmed", False), resp_time)

            if self.adaptive:
                if validation.get("confirmed"):
                    self.adaptive.record_success(flow.vuln_type, endpoint, step.payload, validation.get("confidence", "high"))
                else:
                    self.adaptive.record_failure(flow.vuln_type, endpoint, step.payload, validation.get("reason", ""))

            self._update_confidence(flow, validation)

            flow.step_log.append({
                "step": step.name,
                "technique": step.technique,
                "status": status.value,
                "validation": validation.get("reason", ""),
                "confidence": flow.confidence,
            })

            flow.current_step_index += 1

            if not validation.get("confirmed"):
                flow.consecutive_failures += 1
                if flow.consecutive_failures >= 6:
                    self._log(f"Early abort: {flow.consecutive_failures} consecutive failures")
                    flow.stop_reason = "too_many_failures"
                    flow.result = FlowResult.REJECTED
                    return False

            if validation.get("confirmed"):
                stage_confirmed = True
                flow.consecutive_failures = 0
                finding = {
                    "type": flow.vuln_type,
                    "param": param,
                    "stage": stage_config["name"],
                    "step": step.name,
                    "technique": step.technique,
                    "payload": step.payload,
                    "validation_status": validation.get("confidence", "high"),
                    "reason": validation.get("reason", ""),
                    "confidence": validation.get("confidence", "high"),
                }
                flow.confirmed_findings.append(finding)

                if validation.get("confidence") == "high":
                    self._log(f"Confirmed {flow.vuln_type} at stage {stage_config['name']}")
                    if stage_confirmed:
                        break

        return stage_confirmed

    async def execute_flow(self, vuln_type: str, endpoint: str, param: str, baseline_response: dict) -> dict:
        self._flow_log = []
        self._log(f"Starting attack flow for {vuln_type} on {endpoint} (param: {param})")

        if self.adaptive:
            initial_conf = self.adaptive.get_initial_confidence(vuln_type, endpoint)
            profile = self.adaptive.get_endpoint_profile(endpoint)
            if profile.get("vuln_types_detected"):
                self._log(f"Endpoint profile applied: {endpoint}")
            flow = FlowState(
                vuln_type=vuln_type,
                endpoint=endpoint,
                param=param,
                baseline_response=baseline_response,
                confidence=initial_conf,
            )
        else:
            flow = FlowState(
                vuln_type=vuln_type,
                endpoint=endpoint,
                param=param,
                baseline_response=baseline_response,
            )

        chain = self._get_escalation_chain(vuln_type)

        for stage_config in chain:
            if self._should_stop(flow):
                break

            flow.escalation_stage = stage_config["stage"]
            self._log(f"Entering stage {stage_config['stage']}: {stage_config['name']} - {stage_config['description']}")

            stage_confirmed = await self._run_escalation_stage(
                flow, endpoint, param, stage_config
            )

            if stage_confirmed and flow.confidence >= 0.7:
                if stage_config.get("next_stage_on_success", -1) == -1:
                    flow.stop_reason = "confirmed_and_escalation_complete"
                    break
                else:
                    self._log(f"Success -> escalating to next stage")
            elif not stage_confirmed:
                if stage_config.get("next_stage_on_weak", -1) == -1:
                    if len(flow.confirmed_findings) > 0:
                        flow.stop_reason = "confirmed_no_further_escalation"
                    else:
                        flow.stop_reason = "exhausted_all_stages"
                        flow.result = FlowResult.REJECTED
                    break
                else:
                    self._log(f"No confirmation at stage {stage_config['stage']}, continuing")

        if not flow.stop_reason:
            if len(flow.confirmed_findings) > 0:
                flow.stop_reason = "flow_complete_with_findings"
            else:
                flow.stop_reason = "flow_complete_no_findings"
                flow.result = FlowResult.REJECTED

        self._log(f"Final result: {flow.result.value} (confidence: {flow.confidence:.2f}, findings: {len(flow.confirmed_findings)}, stop: {flow.stop_reason})")

        return {
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "param": param,
            "result": flow.result.value,
            "confidence": flow.confidence,
            "findings": flow.confirmed_findings,
            "escalation_stages_completed": flow.escalation_stage + 1,
            "steps_executed": flow.current_step_index,
            "stop_reason": flow.stop_reason,
            "step_log": flow.step_log,
            "flow_log": self._flow_log.copy(),
        }

    async def execute_multi_vuln_flow(self, vuln_types: list, endpoint: str, params: list, baseline_response: dict) -> list:
        all_results = []

        for vuln_type in vuln_types:
            for param in params:
                result = await self.execute_flow(vuln_type, endpoint, param, baseline_response)
                all_results.append(result)

        return all_results
