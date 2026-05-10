"""
BugHunter AI Elite - Confidence Engine
False positive reduction and validation quality improvement.
"""

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from enum import Enum
from urllib.parse import unquote, quote

logger = logging.getLogger(__name__)


class ConfidenceLevel(Enum):
    INFORMATIONAL = "informational"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    VERIFIED = "verified"


class ReflectionType(Enum):
    RAW = "raw"
    ENCODED = "encoded"
    SANITIZED = "sanitized"
    PARTIAL = "partial"
    EXECUTABLE = "executable"
    NONE = "none"


class ExecutionContext(Enum):
    HTML = "html"
    JAVASCRIPT = "javascript"
    ATTRIBUTE = "attribute"
    URL = "url"
    TEMPLATE = "template"
    COMMENT = "comment"
    STYLE = "style"
    JSON = "json"
    UNKNOWN = "unknown"


@dataclass
class ReflectionAnalysis:
    reflection_type: str = ReflectionType.NONE.value
    reflection_score: float = 0.0
    reflected_content: str = ""
    position: int = -1
    is_partial: bool = False
    is_encoded: bool = False
    is_sanitized: bool = False
    is_executable: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "reflection_type": self.reflection_type,
            "reflection_score": round(self.reflection_score, 2),
            "reflected_content": self.reflected_content[:100],
            "position": self.position,
            "is_partial": self.is_partial,
            "is_encoded": self.is_encoded,
            "is_sanitized": self.is_sanitized,
            "is_executable": self.is_executable,
        }


@dataclass
class ContextAnalysis:
    context_type: str = ExecutionContext.UNKNOWN.value
    confidence_boost: float = 0.0
    matching_tags: List[str] = field(default_factory=list)
    safe_elements: List[str] = field(default_factory=list)
    dangerous_elements: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "context_type": self.context_type,
            "confidence_boost": round(self.confidence_boost, 2),
            "matching_tags": self.matching_tags,
            "safe_elements": self.safe_elements,
            "dangerous_elements": self.dangerous_elements,
        }


@dataclass
class ValidationSignal:
    signal_type: str
    weight: float
    score: float
    evidence: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "signal_type": self.signal_type,
            "weight": self.weight,
            "score": round(self.score, 2),
            "evidence": self.evidence,
        }


@dataclass
class ConfidenceScore:
    overall: float = 0.0
    level: str = ConfidenceLevel.INFORMATIONAL.value
    signals: List[ValidationSignal] = field(default_factory=list)
    reflection_analysis: Optional[ReflectionAnalysis] = None
    context_analysis: Optional[ContextAnalysis] = None
    payload_effectiveness: float = 0.0
    validator_agreement: float = 0.0
    is_likely_false_positive: bool = False
    
    def to_dict(self) -> Dict:
        return {
            "overall": round(self.overall, 2),
            "level": self.level,
            "signals": [s.to_dict() for s in self.signals],
            "reflection": self.reflection_analysis.to_dict() if self.reflection_analysis else None,
            "context": self.context_analysis.to_dict() if self.context_analysis else None,
            "payload_effectiveness": round(self.payload_effectiveness, 2),
            "validator_agreement": round(self.validator_agreement, 2),
            "is_likely_false_positive": self.is_likely_false_positive,
        }


class ConfidenceEngine:
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
        
        self._payload_effectiveness: Dict[str, Dict] = {}
        self._validator_results: Dict[str, List] = {}
        self._max_history = 1000
        
        self._reflection_patterns = self._load_reflection_patterns()
        self._context_patterns = self._load_context_patterns()
        self._sanitization_patterns = self._load_sanitization_patterns()
    
    def _load_reflection_patterns(self) -> Dict[str, List[str]]:
        return {
            "executable": [
                "<script", "javascript:", "onerror=", "onload=",
                "onclick=", "onfocus=", "eval(", "alert(",
                "svg onload", "body onload"
            ],
            "encoded": [
                "%3Cscript", "%3C", "&#60", "\\x3C",
                "u003C", "&#x3c"
            ],
            "partial": [
                "<sc", "<scri", "<scr", "<scrip"
            ],
            "attribute": [
                "onerror", "onload", "onclick", "onfocus",
                "onmouseover", "onkeydown", "onsubmit"
            ]
        }
    
    def _load_context_patterns(self) -> Dict[str, Dict]:
        return {
            "html": {
                "tags": ["<html", "<body", "<div", "<span", "<p>", "<a href"],
                "confidence_boost": 0.3
            },
            "javascript": {
                "keywords": ["function", "var ", "const ", "let ", ".addEventListener"],
                "confidence_boost": 0.4
            },
            "attribute": {
                "attributes": ["onclick", "onerror", "onload", "onmouseover", "href="],
                "confidence_boost": 0.5
            },
            "url": {
                "patterns": ["href=", "src=", "action=", "url=", "redirect="],
                "confidence_boost": 0.2
            },
            "template": {
                "markers": ["{{", "}}", "<%= ", "%>", "${", "#{", "{%"],
                "confidence_boost": 0.4
            },
            "json": {
                "markers": ["{\"", "\"key\"", "JSON.parse"],
                "confidence_boost": 0.3
            },
            "comment": {
                "markers": ["<!--", "-->", "/*", "*/"],
                "confidence_boost": -0.2
            }
        }
    
    def _load_sanitization_patterns(self) -> List[str]:
        return [
            r"<[^>]*>",
            r"&lt;",
            r"&gt;",
            r"&amp;",
            r"&#",
            r"\\x",
            r"\\u",
        ]
    
    def analyze_reflection(self, payload: str, response_text: str) -> ReflectionAnalysis:
        analysis = ReflectionAnalysis()
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        if not response_text or not payload:
            return analysis
        
        if payload in response_text:
            analysis.reflection_type = ReflectionType.RAW.value
            analysis.reflected_content = payload
            analysis.reflection_score = 1.0
            analysis.position = response_text.find(payload)
        
        elif payload_lower in response_lower:
            idx = response_lower.find(payload_lower)
            if idx >= 0:
                analysis.reflection_type = ReflectionType.RAW.value
                analysis.reflected_content = response_text[idx:idx+len(payload)]
                analysis.reflection_score = 0.9
                analysis.position = idx
        
        for pattern in self._reflection_patterns["encoded"]:
            if pattern.lower() in response_lower or pattern in payload:
                analysis.is_encoded = True
                analysis.reflection_type = ReflectionType.ENCODED.value
                analysis.reflection_score = max(analysis.reflection_score, 0.7)
                break
        
        for pattern in self._reflection_patterns["partial"]:
            if pattern in response_text[:100]:
                analysis.is_partial = True
                analysis.reflection_type = ReflectionType.PARTIAL.value
                analysis.reflection_score = max(analysis.reflection_score, 0.4)
                break
        
        for pattern in self._sanitization_patterns:
            if re.search(pattern, response_text):
                analysis.is_sanitized = True
                if analysis.reflection_score < 0.8:
                    analysis.reflection_type = ReflectionType.SANITIZED.value
                break
        
        for pattern in self._reflection_patterns["executable"]:
            if pattern.lower() in response_lower:
                analysis.is_executable = True
                if "script" in pattern or "javascript" in pattern:
                    analysis.reflection_type = ReflectionType.EXECUTABLE.value
                    analysis.reflection_score = 1.0
                break
        
        if analysis.reflection_score > 0 and analysis.reflection_type == ReflectionType.NONE.value:
            analysis.reflection_type = ReflectionType.PARTIAL.value
        
        return analysis
    
    def analyze_context(self, response_text: str, param: str = "") -> ContextAnalysis:
        analysis = ContextAnalysis()
        
        if not response_text:
            return analysis
        
        response_lower = response_text.lower()
        
        highest_boost = 0.0
        best_context = ExecutionContext.UNKNOWN.value
        
        for context_name, context_data in self._context_patterns.items():
            matches = 0
            
            if "tags" in context_data:
                for tag in context_data["tags"]:
                    if tag.lower() in response_lower:
                        matches += 1
                        analysis.matching_tags.append(tag)
            
            elif "keywords" in context_data:
                for keyword in context_data["keywords"]:
                    if keyword.lower() in response_lower:
                        matches += 1
            
            elif "attributes" in context_data:
                for attr in context_data["attributes"]:
                    if attr.lower() in response_lower:
                        matches += 1
            
            elif "patterns" in context_data:
                for pattern in context_data["patterns"]:
                    if pattern.lower() in response_lower:
                        matches += 1
            
            elif "markers" in context_data:
                for marker in context_data["markers"]:
                    if marker in response_text:
                        matches += 1
                        if context_name == "comment":
                            analysis.safe_elements.append(marker)
            
            if matches > 0:
                boost = context_data.get("confidence_boost", 0.1) * min(matches, 3)
                if boost > highest_boost:
                    highest_boost = boost
                    best_context = context_name
        
        analysis.context_type = best_context
        analysis.confidence_boost = highest_boost
        
        return analysis
    
    def calculate_confidence(
        self,
        payload: str,
        response_text: str,
        param: str,
        validator_results: Optional[List[Dict]] = None,
        payload_history: Optional[Dict] = None
    ) -> ConfidenceScore:
        score = ConfidenceScore()
        
        reflection = self.analyze_reflection(payload, response_text)
        score.reflection_analysis = reflection
        
        if reflection.reflection_score > 0:
            score.signals.append(ValidationSignal(
                signal_type="reflection",
                weight=0.35,
                score=reflection.reflection_score,
                evidence=f"type: {reflection.reflection_type}"
            ))
        
        context = self.analyze_context(response_text, param)
        score.context_analysis = context
        
        if context.confidence_boost > 0:
            score.signals.append(ValidationSignal(
                signal_type="context",
                weight=0.25,
                score=min(context.confidence_boost, 0.8),
                evidence=f"context: {context.context_type}"
            ))
        
        if validator_results:
            confirmed = sum(1 for r in validator_results if r.get("confirmed"))
            total = len(validator_results)
            
            if total > 0:
                validator_agreement = confirmed / total
                score.validator_agreement = validator_agreement
                
                score.signals.append(ValidationSignal(
                    signal_type="validator_agreement",
                    weight=0.25,
                    score=validator_agreement,
                    evidence=f"{confirmed}/{total} validators"
                ))
        
        if payload_history:
            success_rate = payload_history.get("success_rate", 0.5)
            usage_count = payload_history.get("usage_count", 1)
            
            if usage_count >= 3:
                score.payload_effectiveness = success_rate
                
                score.signals.append(ValidationSignal(
                    signal_type="payload_effectiveness",
                    weight=0.15,
                    score=success_rate,
                    evidence=f"history: {usage_count} uses"
                ))
        
        total_weight = sum(s.weight for s in score.signals)
        
        if total_weight > 0:
            weighted_score = sum(s.score * s.weight for s in score.signals) / total_weight
            score.overall = weighted_score
        
        if score.overall >= 0.85:
            score.level = ConfidenceLevel.VERIFIED.value
        elif score.overall >= 0.7:
            score.level = ConfidenceLevel.STRONG.value
        elif score.overall >= 0.5:
            score.level = ConfidenceLevel.MODERATE.value
        elif score.overall >= 0.3:
            score.level = ConfidenceLevel.WEAK.value
        else:
            score.level = ConfidenceLevel.INFORMATIONAL.value
        
        if score.overall < 0.3 and reflection.reflection_score > 0:
            if reflection.is_sanitized or reflection.is_partial:
                score.is_likely_false_positive = True
        
        if score.overall < 0.2 and not reflection.is_executable:
            score.is_likely_false_positive = True
        
        return score
    
    def record_payload_result(
        self,
        payload_id: str,
        vuln_type: str,
        success: bool
    ):
        if vuln_type not in self._payload_effectiveness:
            self._payload_effectiveness[vuln_type] = {}
        
        if payload_id not in self._payload_effectiveness[vuln_type]:
            self._payload_effectiveness[vuln_type][payload_id] = {
                "successes": 0,
                "failures": 0,
                "usage_count": 0,
                "success_rate": 0.0
            }
        
        data = self._payload_effectiveness[vuln_type][payload_id]
        
        if success:
            data["successes"] += 1
        else:
            data["failures"] += 1
        
        data["usage_count"] += 1
        
        if data["usage_count"] > 0:
            data["success_rate"] = data["successes"] / data["usage_count"]
    
    def get_payload_effectiveness(self, payload_id: str, vuln_type: str) -> Dict:
        if vuln_type in self._payload_effectiveness:
            if payload_id in self._payload_effectiveness[vuln_type]:
                return self._payload_effectiveness[vuln_type][payload_id]
        
        return {"successes": 0, "failures": 0, "usage_count": 0, "success_rate": 0.0}
    
    def record_validator_result(self, vuln_type: str, finding_id: str, result: Dict):
        key = f"{vuln_type}:{finding_id}"
        
        if key not in self._validator_results:
            self._validator_results[key] = []
        
        self._validator_results[key].append(result)
        
        if len(self._validator_results[key]) > self._max_history:
            self._validator_results[key] = self._validator_results[key][-self._max_history:]
    
    def get_validator_agreement(self, vuln_type: str, finding_id: str) -> float:
        key = f"{vuln_type}:{finding_id}"
        
        if key not in self._validator_results:
            return 0.5
        
        results = self._validator_results[key]
        
        if not results:
            return 0.5
        
        confirmed = sum(1 for r in results if r.get("confirmed"))
        return confirmed / len(results)
    
    def analyze_response_quality(self, response_text: str, status_code: int) -> Dict:
        quality = {
            "is_error_page": False,
            "is_waf_response": False,
            "is_redirect": False,
            "is_empty": False,
            "is_standard_error": False,
            "quality_score": 1.0
        }
        
        response_lower = response_text.lower() if response_text else ""
        
        error_indicators = [
            "access denied", "forbidden", "blocked", "security check",
            "waf", "firewall", "rate limit", "too many requests"
        ]
        
        for indicator in error_indicators:
            if indicator in response_lower:
                quality["is_waf_response"] = True
                quality["quality_score"] = 0.2
                break
        
        if status_code in [403, 429, 503]:
            quality["is_error_page"] = True
            quality["quality_score"] = 0.3
        
        if 300 <= status_code < 400:
            quality["is_redirect"] = True
            quality["quality_score"] = 0.5
        
        if not response_text or len(response_text) < 10:
            quality["is_empty"] = True
            quality["quality_score"] = 0.1
        
        return quality


_confidence_instance: Optional[ConfidenceEngine] = None


def get_confidence_engine(config: Optional[Dict] = None) -> ConfidenceEngine:
    global _confidence_instance
    
    if _confidence_instance is None:
        _confidence_instance = ConfidenceEngine(config)
    
    return _confidence_instance


def calculate_confidence(
    payload: str,
    response_text: str,
    param: str,
    validator_results: Optional[List[Dict]] = None,
    payload_history: Optional[Dict] = None
) -> Dict:
    engine = get_confidence_engine()
    score = engine.calculate_confidence(
        payload, response_text, param, validator_results, payload_history
    )
    return score.to_dict()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("\n=== Confidence Engine Test ===\n")
    
    engine = get_confidence_engine()
    
    test_cases = [
        ("<script>alert(1)</script>", "<html><body><script>alert(1)</script></body></html>"),
        ("<img src=x onerror=alert(1)>", '<div><img src="x" onerror="alert(1)"></div>'),
        ("' OR '1'='1", "SELECT * FROM users WHERE id = '' OR '1'='1'"),
        ("{{7*7}}", "<div>{{7*7}}</div>"),
    ]
    
    for payload, response in test_cases:
        score = engine.calculate_confidence(payload, response, "test")
        
        print(f"\nPayload: {payload[:30]}...")
        print(f"  Confidence: {score.overall:.2f} ({score.level})")
        print(f"  Reflection: {score.reflection_analysis.reflection_type if score.reflection_analysis else 'none'}")
        print(f"  Context: {score.context_analysis.context_type if score.context_analysis else 'none'}")
        print(f"  FP Risk: {score.is_likely_false_positive}")
        
        for signal in score.signals:
            print(f"    Signal: {signal.signal_type} = {signal.score:.2f} (weight: {signal.weight})")