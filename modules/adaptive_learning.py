"""
Adaptive Learning Controller - Enhances Attack Flow Engine with learning-driven decisions.

Uses existing learning_db.json and RAG learning patterns to:
- Prioritize successful payloads
- Avoid repeatedly failed payloads
- Boost confidence on pattern matches
- Profile endpoints for targeted testing
- Dynamically adjust confidence during flows
- Integrate retest logic from RAG rules

DOES NOT modify RAG files, payloads, or existing attack flow engine.
Adds a new adaptive decision layer only.
"""

import json
import re
import hashlib
import os
from datetime import datetime, timedelta
from typing import Any
from modules.logging_config import logger


FAILURE_THRESHOLD = 3
SUCCESS_MINIMUM = 2
RETEST_WEIGHT_THRESHOLD = 0.5
RETEST_DAYS_WINDOW = 30
CONFIDENCE_BOOST_STRONG = 0.15
CONFIDENCE_BOOST_WEAK = 0.05
CONFIDENCE_PENALTY_REPEATED = 0.08

FAILURE_THRESHOLDS_BY_TYPE = {
    "xss": 3,
    "sqli": 5,
    "ssrf": 5,
    "xxe": 6,
    "ssti": 6,
    "command_injection": 5,
    "path_traversal": 5,
    "deserialization": 6,
    "open_redirect": 3,
    "csrf": 4,
    "idor": 4,
    "jwt": 5,
    "graphql": 4,
    "race_conditions": 8,
}

def get_failure_threshold(vuln_type: str) -> int:
    return FAILURE_THRESHOLDS_BY_TYPE.get(vuln_type, FAILURE_THRESHOLD)


DECAY_FACTORS = {
    30: 0.8,
    60: 0.5,
    90: 0.3,
    180: 0.1,
}

VULN_CONTEXT_SIGNS = {
    "xss": ["reflected", "stored", "dom", "blind", "html_entities", "csp", "waf"],
    "sqli": ["error_based", "union", "blind", "time_based", "stacked", "second_order"],
    "ssrf": ["internal", "bypass", "cloud_metadata", "blind", "dns"],
    "xxe": ["entity", "file_read", "blind", "ssrf_via_xxe", "soap", "svg"],
    "ssti": ["arithmetic", "engine", "rce", "sandbox", "jinja", "twig", "freemarker"],
    "command_injection": ["basic", "blind", "filter_bypass", "oob", "pipe", "semicolon"],
    "path_traversal": ["basic", "null_byte", "encoding", "sensitive", "windows", "linux"],
    "idor": ["horizontal", "vertical", "enumeration", "uuid", "insecure_direct"],
    "open_redirect": ["basic", "encoded", "double_encoded", "protocol", "whitelist_bypass"],
    "csrf": ["token_missing", "token_bypass", "samesite", "cors", "preflight"],
    "deserialization": ["probe", "gadget", "rce", "blind", "java", "php", "python"],
    "jwt": ["none_alg", "weak_key", "claim_manipulation", "hs256_rs256", "expired"],
    "graphql": ["introspection", "batching", "injection", "dos", "authorization"],
    "race_conditions": ["timing", "concurrent", "turbo", "limit_bypass", "toctou"],
}


class AdaptiveLearningController:
    """Adaptive decision layer for Attack Flow Engine.

    Wraps the existing LearningSystem and adds:
    - Payload prioritization based on past success/failure
    - Failure avoidance with configurable thresholds
    - Success boosting with pattern matching
    - Endpoint profiling for targeted testing
    - Dynamic confidence adjustment during flows
    - Retest logic from RAG learning rules
    """

    def __init__(self, learning_system, rag_loader=None, db_path="learning_db.json"):
        self.learning = learning_system
        self.rag_loader = rag_loader
        self.db_path = db_path
        self._rag_learning_cache = {}
        self._endpoint_profiles = {}
        self._session_failures = {}
        self._session_successes = {}

    def _log(self, message: str):
        logger.info(f"[LEARN] {message}")

    def _load_learning_db(self) -> dict:
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _get_rag_learning_config(self, vuln_type: str) -> dict:
        if vuln_type in self._rag_learning_cache:
            return self._rag_learning_cache[vuln_type]
        if self.rag_loader:
            try:
                config = self.rag_loader.get_learning_config(vuln_type)
                self._rag_learning_cache[vuln_type] = config
                return config
            except Exception:
                pass
        self._rag_learning_cache[vuln_type] = {}
        return {}

    def _days_since(self, iso_timestamp: str) -> float:
        try:
            dt = datetime.fromisoformat(iso_timestamp)
            return (datetime.now() - dt).days
        except Exception:
            return 999

    def _get_decay_factor(self, iso_timestamp: str) -> float:
        days = self._days_since(iso_timestamp)
        for threshold in sorted(DECAY_FACTORS.keys()):
            if days >= threshold:
                continue
            return DECAY_FACTORS.get(threshold, 1.0)
        return DECAY_FACTORS[180]

    def _is_similar_pattern(self, pattern1: str, pattern2: str) -> bool:
        normalized1 = re.sub(r"\d+", "{ID}", pattern1)
        normalized2 = re.sub(r"\d+", "{ID}", pattern2)
        return normalized1 == normalized2

    # Payload Prioritization

    def prioritize_payloads(self, vuln_type: str, endpoint: str, candidate_payloads: list) -> list:
        """Reorder candidate payloads based on learning data.

        Rules:
        - Previously successful payloads move to top
        - Frequently failed payloads are deprioritized or skipped
        - New endpoints use default RAG order
        """
        db = self._load_learning_db()
        successful = db.get("successful_payloads", {})
        param_eff = db.get("param_effectiveness", {})

        prioritized = []
        skipped = []
        deprioritized = []
        normal = []

        endpoint_pattern = self._extract_endpoint_pattern(endpoint)

        for payload in candidate_payloads:
            payload_str = payload if isinstance(payload, str) else payload.get("value", payload.get("payload", str(payload)))
            payload_key = hashlib.md5(f"{vuln_type}:{payload_str}".encode()).hexdigest()
            eff_key = f"{vuln_type}:{endpoint}"

            success_data = successful.get(payload_key)
            eff_data = param_eff.get(eff_key, {})
            fp_count = eff_data.get("false_positives", 0)
            tp_count = eff_data.get("true_positives", 0)

            session_fail = self._session_failures.get(f"{vuln_type}:{payload_str}", 0)
            session_success = self._session_successes.get(f"{vuln_type}:{payload_str}", 0)

            if success_data and success_data.get("success_count", 0) >= SUCCESS_MINIMUM:
                decay = self._get_decay_factor(success_data.get("last_seen", ""))
                weight = success_data["success_count"] * decay

                target_match = endpoint in success_data.get("targets", [])
                pattern_match = self._is_similar_pattern(endpoint_pattern, success_data.get("pattern", ""))

                if target_match:
                    weight *= 3.0
                    self._log(f"Prioritizing payload (exact match, {success_data['success_count']} successes): {payload_str[:60]}")
                elif pattern_match:
                    weight *= 2.0
                    self._log(f"Prioritizing payload (similar pattern, {success_data['success_count']} successes): {payload_str[:60]}")
                else:
                    self._log(f"Prioritizing payload based on past success ({success_data['success_count']} successes): {payload_str[:60]}")

                prioritized.append((weight, payload))

            elif fp_count >= get_failure_threshold(vuln_type) or session_fail >= get_failure_threshold(vuln_type):
                self._log(f"Skipping payload (failed {max(fp_count, session_fail)} times, threshold={get_failure_threshold(vuln_type)}): {payload_str[:60]}")
                skipped.append(payload)

            elif fp_count >= get_failure_threshold(vuln_type) - 1 or session_fail >= get_failure_threshold(vuln_type) - 1:
                self._log(f"Deprioritizing payload (failed {max(fp_count, session_fail)} times, threshold={get_failure_threshold(vuln_type)}): {payload_str[:60]}")
                deprioritized.append((1.0, payload))

            else:
                normal.append((0.5, payload))

        prioritized.sort(key=lambda x: x[0], reverse=True)
        deprioritized.sort(key=lambda x: x[0], reverse=True)

        result = [p[1] for p in prioritized] + [p[1] for p in normal] + [p[1] for p in deprioritized]
        return result

    def _extract_endpoint_pattern(self, url: str) -> str:
        pattern = re.sub(r"\d+", "{ID}", url)
        pattern = re.sub(r"[a-f0-9]{8,}", "{HASH}", pattern)
        pattern = re.sub(r"[\w\-]+@[\w\-.]+", "{EMAIL}", pattern)
        return pattern

    # Failure Avoidance

    def should_skip_payload(self, vuln_type: str, endpoint: str, payload: str) -> bool:
        """Check if a payload should be skipped due to repeated failures."""
        db = self._load_learning_db()
        param_eff = db.get("param_effectiveness", {})
        eff_key = f"{vuln_type}:{endpoint}"
        eff_data = param_eff.get(eff_key, {})
        fp_count = eff_data.get("false_positives", 0)

        session_fail = self._session_failures.get(f"{vuln_type}:{payload}", 0)
        threshold = get_failure_threshold(vuln_type)

        if fp_count >= threshold or session_fail >= threshold:
            self._log(f"Skipping payload (failed {max(fp_count, session_fail)} times on {vuln_type}, threshold={threshold})")
            return True
        return False

    def record_failure(self, vuln_type: str, endpoint: str, payload: str, reason: str = ""):
        """Record a payload failure for future avoidance."""
        key = f"{vuln_type}:{payload}"
        self._session_failures[key] = self._session_failures.get(key, 0) + 1

        db = self._load_learning_db()
        param_eff = db.get("param_effectiveness", {})
        eff_key = f"{vuln_type}:{endpoint}"
        if eff_key not in param_eff:
            param_eff[eff_key] = {"false_positives": 0, "true_positives": 0}
        param_eff[eff_key]["false_positives"] = param_eff[eff_key].get("false_positives", 0) + 1

        if "param_effectiveness" in db:
            db["param_effectiveness"] = param_eff
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(db, f, indent=2)
        except Exception:
            pass

        self._log(f"Recorded failure for {vuln_type}/{payload[:40]} (session count: {self._session_failures[key]})")

    def record_success(self, vuln_type: str, endpoint: str, payload: str, confidence: str = "high"):
        """Record a payload success for future prioritization."""
        key = f"{vuln_type}:{payload}"
        self._session_successes[key] = self._session_successes.get(key, 0) + 1

        if self.learning:
            try:
                pattern = self._extract_endpoint_pattern(endpoint)
                self.learning.record_successful_payload(vuln_type, pattern, payload, "", success=True)
                self.learning.record_true_positive(vuln_type, endpoint)
            except Exception:
                pass

        self._log(f"Recorded success for {vuln_type}/{payload[:40]} (confidence: {confidence})")

    # Success Boosting

    def get_success_boost(self, vuln_type: str, endpoint: str, payload: str, validation_signal: bool = False) -> float:
        """Calculate confidence boost based on past successes.

        Requires validation_signal=True to apply boost.
        Raw pattern matches alone do not trigger boost.
        """
        if not validation_signal:
            return 0.0

        db = self._load_learning_db()
        successful = db.get("successful_payloads", {})
        boost = 0.0

        payload_str = payload if isinstance(payload, str) else payload.get("value", payload.get("payload", str(payload)))
        payload_key = hashlib.md5(f"{vuln_type}:{payload_str}".encode()).hexdigest()

        success_data = successful.get(payload_key)
        if success_data:
            success_count = success_data.get("success_count", 0)
            decay = self._get_decay_factor(success_data.get("last_seen", ""))
            boost = min(0.15, success_count * 0.03 * decay)

            if endpoint in success_data.get("targets", []):
                boost += 0.05
                self._log(f"Boosting confidence (exact endpoint match + validation): +0.05")

            self._log(f"Success boost for {vuln_type}: +{boost:.2f} (validated, {success_count} past successes, decay={decay:.2f})")

        return boost

    def has_successful_history(self, vuln_type: str, endpoint: str) -> bool:
        """Check if this vuln type has succeeded on this or similar endpoints before."""
        db = self._load_learning_db()
        successful = db.get("successful_payloads", {})
        endpoint_pattern = self._extract_endpoint_pattern(endpoint)

        for data in successful.values():
            if data.get("vuln_type") != vuln_type:
                continue
            if data.get("success_count", 0) < SUCCESS_MINIMUM:
                continue
            if endpoint in data.get("targets", []):
                return True
            if self._is_similar_pattern(endpoint_pattern, data.get("pattern", "")):
                return True
        return False

    # Pattern-Based Learning (RAG integration)

    def get_rag_context_priorities(self, vuln_type: str) -> list:
        """Get context priorities from RAG learning patterns.

        Example: XSS reflected -> prioritize similar payload contexts
        """
        config = self._get_rag_learning_config(vuln_type)
        success_patterns_raw = config.get("SUCCESS_PATTERNS", "")

        if not success_patterns_raw or not isinstance(success_patterns_raw, str):
            return []

        priorities = []
        current_pattern = None
        current_data = {}

        for line in success_patterns_raw.split("\n"):
            line = line.rstrip()
            if not line or line.startswith("["):
                if current_pattern and current_data:
                    priorities.append({
                        "pattern": current_pattern,
                        "tag": current_data.get("tag", current_pattern),
                        "boost": current_data.get("confidence_boost", 0),
                        "condition": current_data.get("condition", ""),
                    })
                current_pattern = None
                current_data = {}
                continue

            if line.startswith("pattern_") and ":" in line:
                if current_pattern and current_data:
                    priorities.append({
                        "pattern": current_pattern,
                        "tag": current_data.get("tag", current_pattern),
                        "boost": current_data.get("confidence_boost", 0),
                        "condition": current_data.get("condition", ""),
                    })
                current_pattern = line.split(":")[0].strip()
                current_data = {}
            elif current_pattern and ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if key == "confidence_boost":
                    try:
                        value = value.lstrip("+")
                        current_data[key] = int(value)
                    except ValueError:
                        try:
                            current_data[key] = float(value)
                        except ValueError:
                            current_data[key] = value
                elif key == "tag":
                    current_data[key] = value
                elif key == "condition":
                    current_data[key] = value
                elif key == "action":
                    pass
                else:
                    current_data[key] = value

        if current_pattern and current_data:
            priorities.append({
                "pattern": current_pattern,
                "tag": current_data.get("tag", current_pattern),
                "boost": current_data.get("confidence_boost", 0),
                "condition": current_data.get("condition", ""),
            })

        if priorities:
            self._log(f"RAG learning priorities for {vuln_type}: {[p['tag'] for p in priorities]}")

        return priorities

    def match_context_to_rag_pattern(self, vuln_type: str, observed_indicators: list) -> dict:
        """Match observed indicators to RAG learning patterns for confidence boost."""
        config = self._get_rag_learning_config(vuln_type)
        success_patterns_raw = config.get("SUCCESS_PATTERNS", "")

        if not success_patterns_raw or not isinstance(success_patterns_raw, str):
            return {"pattern": None, "boost": 0}

        best_match = None
        best_boost = 0

        current_pattern = None
        current_data = {}

        for line in success_patterns_raw.split("\n"):
            line = line.rstrip()
            if not line or line.startswith("["):
                if current_pattern and current_data:
                    condition = current_data.get("condition", "").lower()
                    boost = current_data.get("confidence_boost", 0)
                    for indicator in observed_indicators:
                        indicator_lower = indicator.lower()
                        if any(term in indicator_lower for term in condition.split("_")):
                            if boost > best_boost:
                                best_match = current_pattern
                                best_boost = boost
                current_pattern = None
                current_data = {}
                continue

            if line.startswith("pattern_") and ":" in line:
                if current_pattern and current_data:
                    condition = current_data.get("condition", "").lower()
                    boost = current_data.get("confidence_boost", 0)
                    for indicator in observed_indicators:
                        indicator_lower = indicator.lower()
                        if any(term in indicator_lower for term in condition.split("_")):
                            if boost > best_boost:
                                best_match = current_pattern
                                best_boost = boost
                current_pattern = line.split(":")[0].strip()
                current_data = {}
            elif current_pattern and ":" in line:
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if key == "confidence_boost":
                    try:
                        value = value.lstrip("+")
                        current_data[key] = int(value)
                    except ValueError:
                        try:
                            current_data[key] = float(value)
                        except ValueError:
                            current_data[key] = value
                elif key in ("tag", "condition", "action"):
                    if key != "action":
                        current_data[key] = value
                else:
                    current_data[key] = value

        if current_pattern and current_data:
            condition = current_data.get("condition", "").lower()
            boost = current_data.get("confidence_boost", 0)
            for indicator in observed_indicators:
                indicator_lower = indicator.lower()
                if any(term in indicator_lower for term in condition.split("_")):
                    if boost > best_boost:
                        best_match = current_pattern
                        best_boost = boost

        if best_match:
            self._log(f"Pattern match: {vuln_type} -> {best_match} (boost: +{best_boost})")
            return {"pattern": best_match, "boost": best_boost}

        return {"pattern": None, "boost": 0}

    # Endpoint Profiling

    def get_endpoint_profile(self, endpoint: str) -> dict:
        """Get or build endpoint profile for targeted testing."""
        if endpoint in self._endpoint_profiles:
            return self._endpoint_profiles[endpoint]

        db = self._load_learning_db()
        param_eff = db.get("param_effectiveness", {})
        vuln_history = db.get("vulnerability_history", [])

        profile = {
            "endpoint": endpoint,
            "vuln_types_detected": [],
            "payload_success_rate": {},
            "response_patterns": {},
            "tech_stack": [],
            "last_tested": None,
        }

        for key, data in param_eff.items():
            if endpoint in key:
                vuln_type = key.split(":")[0]
                tp = data.get("true_positives", 0)
                fp = data.get("false_positives", 0)
                total = tp + fp
                if total > 0:
                    profile["vuln_types_detected"].append(vuln_type)
                    profile["payload_success_rate"][vuln_type] = tp / total

        for record in vuln_history:
            if record.get("endpoint") == endpoint:
                vtype = record.get("vuln_type")
                if vtype and vtype not in profile["vuln_types_detected"]:
                    profile["vuln_types_detected"].append(vtype)
                if record.get("timestamp"):
                    profile["last_tested"] = record["timestamp"]

        learned_tech = db.get("learned_tech", {})
        if endpoint in learned_tech:
            profile["tech_stack"] = learned_tech[endpoint].get("technologies", [])

        self._endpoint_profiles[endpoint] = profile

        if profile["vuln_types_detected"]:
            self._log(f"Endpoint profile applied: {endpoint} -> detected types: {profile['vuln_types_detected']}")

        return profile

    def suggest_vuln_order(self, endpoint: str) -> list:
        """Suggest order of vulnerability types to test based on endpoint profile.

        Uses profile data to reorder modules BEFORE flow starts.
        Endpoints with known vuln types get those tested first.
        """
        profile = self.get_endpoint_profile(endpoint)
        detected = profile.get("vuln_types_detected", [])
        success_rates = profile.get("payload_success_rate", {})

        if detected:
            ordered = sorted(detected, key=lambda v: success_rates.get(v, 0), reverse=True)
            self._log(f"Module order from profile: {ordered[:5]} (endpoint has history)")
        else:
            ordered = []

        all_vulns = list(VULN_CONTEXT_SIGNS.keys())
        for v in all_vulns:
            if v not in ordered:
                ordered.append(v)

        if not detected:
            ordered = ordered[:5] + ordered[5:]

        return ordered

    # Dynamic Confidence Adjustment

    def adjust_confidence(self, vuln_type: str, endpoint: str, base_confidence: float,
                          stage_results: list, consecutive_failures: int, consecutive_successes: int) -> float:
        """Dynamically adjust confidence based on flow execution history.

        Rules:
        - Repeated failures reduce confidence faster
        - Consistent success signals boost confidence faster
        """
        adjusted = base_confidence

        if consecutive_failures >= 3:
            penalty = consecutive_failures * CONFIDENCE_PENALTY_REPEATED
            adjusted = max(0.0, adjusted - penalty)
            self._log(f"Confidence reduced ({vuln_type}): -{penalty:.2f} ({consecutive_failures} consecutive failures)")

        if consecutive_successes >= 2:
            boost = consecutive_successes * CONFIDENCE_BOOST_STRONG
            adjusted = min(1.0, adjusted + boost)
            self._log(f"Confidence boosted ({vuln_type}): +{boost:.2f} ({consecutive_successes} consecutive successes)")

        return round(adjusted, 4)

    def get_initial_confidence(self, vuln_type: str, endpoint: str) -> float:
        """Get a starting confidence based on endpoint profile and history."""
        profile = self.get_endpoint_profile(endpoint)
        success_rate = profile.get("payload_success_rate", {}).get(vuln_type, 0)

        if success_rate > 0.5:
            return 0.6
        elif success_rate > 0:
            return 0.3

        if self.has_successful_history(vuln_type, endpoint):
            return 0.5

        return 0.1

    # Retest Logic Integration

    def should_retest(self, vuln_type: str, endpoint: str, last_tested_iso: str = None) -> bool:
        """Determine if an endpoint should be retested based on RAG learning rules.

        Rules from RAG learning:
        - weight < threshold AND days_since_test > 30 -> retest
        - waf_bypass_discovered -> retest old payloads
        - csp_removed_or_weakened -> retest
        - new_context_detected -> retest
        """
        if not last_tested_iso:
            profile = self.get_endpoint_profile(endpoint)
            last_tested_iso = profile.get("last_tested")

        if not last_tested_iso:
            return True

        days_since = self._days_since(last_tested_iso)
        if days_since > RETEST_DAYS_WINDOW:
            self._log(f"Retest triggered: {vuln_type} on {endpoint} (last tested {days_since} days ago)")
            return True

        config = self._get_rag_learning_config(vuln_type)
        bypass_suggestions = config.get("BYPASS_SUGGESTION", {})
        if bypass_suggestions:
            db = self._load_learning_db()
            successful = db.get("successful_payloads", {})
            for data in successful.values():
                if data.get("vuln_type") == vuln_type and data.get("success_count", 0) >= SUCCESS_MINIMUM:
                    if self._is_similar_pattern(endpoint, data.get("pattern", "")):
                        self._log(f"Retest triggered: new bypass discovered for {vuln_type}")
                        return True

        return False

    def get_retest_payloads(self, vuln_type: str, endpoint: str) -> list:
        """Get payloads that should be retested based on RAG retest logic."""
        db = self._load_learning_db()
        successful = db.get("successful_payloads", {})

        retest_payloads = []
        for key, data in successful.items():
            if data.get("vuln_type") != vuln_type:
                continue
            if self._is_similar_pattern(endpoint, data.get("pattern", "")):
                retest_payloads.append({
                    "payload": data.get("payload", ""),
                    "success_count": data.get("success_count", 0),
                    "last_seen": data.get("last_seen", ""),
                    "reason": "retest_due_to_similarity",
                })

        if retest_payloads:
            self._log(f"Retest payloads for {vuln_type}: {len(retest_payloads)} candidates")

        return retest_payloads

    # DB Maintenance: Decay, Pruning, Normalization

    def prune_learning_db(self, max_history: int = 500, max_payloads: int = 200, max_days_old: int = 90) -> dict:
        """Clean up learning_db.json to prevent growth and noise.

        Rules:
        - Remove payloads with 0 success_count and no recent activity
        - Trim vulnerability_history to max_history
        - Trim scan_history to max_history
        - Remove endpoint_patterns with no activity in max_days_old days
        - Normalize duplicate entries
        """
        db = self._load_learning_db()
        stats = {"removed_payloads": 0, "trimmed_history": 0, "trimmed_patterns": 0}

        old_payloads = db.get("successful_payloads", {})
        cleaned_payloads = {}
        for key, data in old_payloads.items():
            if data.get("success_count", 0) == 0:
                days_since = self._days_since(data.get("first_seen", ""))
                if days_since > 30:
                    stats["removed_payloads"] += 1
                    continue
            days_since = self._days_since(data.get("last_seen", data.get("first_seen", "")))
            if days_since > max_days_old and data.get("success_count", 0) < 2:
                stats["removed_payloads"] += 1
                continue
            cleaned_payloads[key] = data

        if len(cleaned_payloads) > max_payloads:
            sorted_payloads = sorted(cleaned_payloads.items(), key=lambda x: x[1].get("success_count", 0), reverse=True)
            cleaned_payloads = dict(sorted_payloads[:max_payloads])
            stats["removed_payloads"] += len(old_payloads) - max_payloads

        db["successful_payloads"] = cleaned_payloads

        vuln_history = db.get("vulnerability_history", [])
        if len(vuln_history) > max_history:
            db["vulnerability_history"] = vuln_history[-max_history:]
            stats["trimmed_history"] += len(vuln_history) - max_history

        scan_history = db.get("scan_history", [])
        if len(scan_history) > max_history:
            db["scan_history"] = scan_history[-max_history:]
            stats["trimmed_history"] += len(scan_history) - max_history

        false_positives = db.get("false_positives", [])
        if len(false_positives) > max_history:
            db["false_positives"] = false_positives[-max_history:]
            stats["trimmed_history"] += len(false_positives) - max_history

        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(db, f, indent=2)
            self._log(f"DB pruned: {stats['removed_payloads']} payloads removed, {stats['trimmed_history']} history entries trimmed")
        except Exception as e:
            self._log(f"DB prune error: {e}")

        return stats

    def normalize_endpoint_patterns(self) -> dict:
        """Normalize duplicate endpoint patterns in the DB.

        Merges patterns that resolve to the same normalized form.
        """
        db = self._load_learning_db()
        patterns = db.get("endpoint_patterns", {})
        merged = {}
        stats = {"duplicates_merged": 0}

        for pattern, data in patterns.items():
            normalized = self._extract_endpoint_pattern(pattern)
            if normalized in merged:
                existing = merged[normalized]
                existing["detection_count"] += data.get("detection_count", 0)
                for p in data.get("patterns", []):
                    if p not in existing["patterns"]:
                        existing["patterns"].append(p)
                stats["duplicates_merged"] += 1
            else:
                merged[normalized] = data

        if stats["duplicates_merged"] > 0:
            db["endpoint_patterns"] = merged
            try:
                with open(self.db_path, "w", encoding="utf-8") as f:
                    json.dump(db, f, indent=2)
                self._log(f"Endpoint patterns normalized: {stats['duplicates_merged']} duplicates merged")
            except Exception:
                pass

        return stats

    def get_db_stats(self) -> dict:
        """Get current learning DB statistics."""
        db = self._load_learning_db()
        return {
            "successful_payloads": len(db.get("successful_payloads", {})),
            "endpoint_patterns": len(db.get("endpoint_patterns", {})),
            "vulnerability_history": len(db.get("vulnerability_history", [])),
            "scan_history": len(db.get("scan_history", [])),
            "false_positives": len(db.get("false_positives", [])),
            "param_effectiveness": len(db.get("param_effectiveness", {})),
            "updated_at": db.get("updated_at"),
        }

    # Compatibility with existing LearningSystem interface

    def suggest_payloads_based_on_learned(self, vuln_type: str, endpoint_pattern: str) -> list:
        """Compatible with flow engine's existing learning interface."""
        return self.get_retest_payloads(vuln_type, endpoint_pattern)

    def record_vulnerability(self, vuln_type: str, endpoint: str, severity: str, confirmed: bool = False):
        """Compatible with flow engine's existing learning interface."""
        if self.learning:
            try:
                self.learning.record_vulnerability(vuln_type, endpoint, severity, confirmed)
            except Exception:
                pass

    def record_true_positive(self, vuln_type: str, endpoint: str):
        """Compatible with flow engine's existing learning interface."""
        if self.learning:
            try:
                self.learning.record_true_positive(vuln_type, endpoint)
            except Exception:
                pass

    def record_successful_payload(self, vuln_type: str, endpoint_pattern: str, payload: str, param: str, success: bool = True):
        """Compatible with flow engine's existing learning interface."""
        if self.learning:
            try:
                self.learning.record_successful_payload(vuln_type, endpoint_pattern, payload, param, success)
            except Exception:
                pass

    def get_endpoint_pattern(self, url: str) -> str:
        """Extract normalized endpoint pattern."""
        return self._extract_endpoint_pattern(url)
