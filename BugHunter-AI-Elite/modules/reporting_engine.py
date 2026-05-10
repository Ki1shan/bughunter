"""
BugHunter AI Elite - Reporting Engine
Professional-grade reporting, evidence management, and finding presentation.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ReportFormat(Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    TERMINAL = "terminal"
    HTML = "html"


@dataclass
class Evidence:
    finding_id: str = ""
    payload: str = ""
    payload_id: str = ""
    response_snippet: str = ""
    status_code: int = 0
    response_time: float = 0.0
    reflection_location: str = ""
    context: str = ""
    validator_output: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "finding_id": self.finding_id,
            "payload": self.payload,
            "payload_id": self.payload_id,
            "response_snippet": self.response_snippet,
            "status_code": self.status_code,
            "response_time": self.response_time,
            "reflection_location": self.reflection_location,
            "context": self.context,
            "validator_output": self.validator_output,
        }


@dataclass
class ExecutionTimelineEvent:
    timestamp: str = ""
    event_type: str = ""
    module: str = ""
    payload_id: str = ""
    status: str = ""
    duration_ms: float = 0.0
    details: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "module": self.module,
            "payload_id": self.payload_id,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "details": self.details,
        }


@dataclass
class PayloadLineage:
    original_payload_id: str = ""
    mutations: List[str] = field(default_factory=list)
    chain: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "original_payload_id": self.original_payload_id,
            "mutations": self.mutations,
            "chain": self.chain,
        }


@dataclass
class Finding:
    finding_id: str = ""
    scan_id: str = ""
    module: str = ""
    vuln_type: str = ""
    severity: str = Severity.MEDIUM.value
    confidence: str = "moderate"
    confidence_score: float = 0.0
    title: str = ""
    description: str = ""
    endpoint: str = ""
    param: str = ""
    method: str = "GET"
    evidence: Evidence = field(default_factory=Evidence)
    timeline: List[ExecutionTimelineEvent] = field(default_factory=list)
    payload_lineage: Optional[PayloadLineage] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cwe_id: str = ""
    wasc_id: str = ""
    cvss_score: Optional[float] = None
    false_positive_likely: bool = False
    timestamp: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "module": self.module,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "title": self.title,
            "description": self.description,
            "endpoint": self.endpoint,
            "param": self.param,
            "method": self.method,
            "evidence": self.evidence.to_dict(),
            "timeline": [e.to_dict() for e in self.timeline],
            "payload_lineage": self.payload_lineage.to_dict() if self.payload_lineage else None,
            "remediation": self.remediation,
            "references": self.references,
            "cwe_id": self.cwe_id,
            "wasc_id": self.wasc_id,
            "cvss_score": self.cvss_score,
            "false_positive_likely": self.false_positive_likely,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanReport:
    scan_id: str = ""
    target: str = ""
    mode: str = "bb_mode"
    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    findings: List[Finding] = field(default_factory=list)
    modules_executed: List[str] = field(default_factory=list)
    total_requests: int = 0
    total_payloads: int = 0
    vulnerabilities_by_severity: Dict[str, int] = field(default_factory=dict)
    execution_stats: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
            "modules_executed": self.modules_executed,
            "total_requests": self.total_requests,
            "total_payloads": self.total_payloads,
            "vulnerabilities_by_severity": self.vulnerabilities_by_severity,
            "execution_stats": self.execution_stats,
        }


class ReportingEngine:
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
        
        self._findings: List[Finding] = []
        self._current_scan: Optional[ScanReport] = None
        self._finding_counter = 0
        self._timeline_cache: List[ExecutionTimelineEvent] = []
        
        self._remediation_templates = self._load_remediation_templates()
        self._cwe_mapping = self._load_cwe_mapping()
    
    def _load_remediation_templates(self) -> Dict[str, str]:
        return {
            "xss": "Implement output encoding appropriate to the context (HTML, attribute, JavaScript, CSS, URL). Use Content Security Policy (CSP) headers. Sanitize user input with a allowlist approach.",
            "sqli": "Use parameterized queries (prepared statements) instead of string concatenation. Validate and sanitize all user inputs. Use least privilege database accounts.",
            "ssrf": "Implement URL validation and allowlist filtering for URLs. Disable HTTP redirection. Use separate networks for internal services.",
            "xxe": "Disable XML external entity processing. Use less complex data formats like JSON. Validate XML input with strict schema.",
            "ssti": "Use template engines with sandboxing. Disable template execution features that allow code execution. Use safe template APIs.",
            "idor": "Implement proper authorization checks. Use indirect references. Validate user ownership of requested resources.",
            "jwt": "Use strong signing algorithms (RS256, ES256). Validate all token claims. Implement token expiration and rotation.",
            "open_redirect": "Validate redirect URLs against an allowlist. Avoid user input in redirect targets. Use relative redirects when possible.",
            "path_traversal": "Validate and sanitize file paths. Use filesystem APIs that prevent traversal. Store files outside web root.",
            "command_injection": "Avoid shell commands when possible. Use language-specific APIs. If needed, use strict allowlists and avoid shell metacharacters.",
            "csrf": "Implement anti-CSRF tokens. Use SameSite cookies. Check Origin/Referer headers for state-changing operations.",
        }
    
    def _load_cwe_mapping(self) -> Dict[str, str]:
        return {
            "xss": "CWE-79",
            "sqli": "CWE-89",
            "ssrf": "CWE-918",
            "xxe": "CWE-611",
            "ssti": "CWE-94",
            "idor": "CWE-639",
            "jwt": "CWE-346",
            "open_redirect": "CWE-601",
            "path_traversal": "CWE-22",
            "command_injection": "CWE-78",
            "csrf": "CWE-352",
        }
    
    def start_scan(self, scan_id: str, target: str, mode: str = "bb_mode") -> ScanReport:
        self._current_scan = ScanReport(
            scan_id=scan_id,
            target=target,
            mode=mode,
            start_time=datetime.now().isoformat()
        )
        self._findings = []
        self._finding_counter = 0
        return self._current_scan
    
    def add_finding(self, finding: Finding) -> str:
        self._finding_counter += 1
        finding.finding_id = f"FIND-{self._finding_counter:05d}"
        
        if not finding.timestamp:
            finding.timestamp = datetime.now().isoformat()
        
        self._findings.append(finding)
        
        if self._current_scan:
            self._current_scan.findings.append(finding)
        
        return finding.finding_id
    
    def create_finding(
        self,
        scan_id: str,
        module: str,
        vuln_type: str,
        endpoint: str,
        param: str,
        payload: str,
        payload_id: str,
        response_snippet: str,
        severity: str,
        confidence: float,
        method: str = "GET"
    ) -> Finding:
        self._finding_counter += 1
        finding_id = f"FIND-{self._finding_counter:05d}"
        
        title = f"{vuln_type.upper()} vulnerability in {param}"
        
        if vuln_type in self._remediation_templates:
            remediation = self._remediation_templates[vuln_type]
        else:
            remediation = "Review and fix the identified vulnerability according to security best practices."
        
        cwe = self._cwe_mapping.get(vuln_type.lower(), "")
        
        evidence = Evidence(
            finding_id=finding_id,
            payload=payload,
            payload_id=payload_id,
            response_snippet=response_snippet[:500]
        )
        
        finding = Finding(
            finding_id=finding_id,
            scan_id=scan_id,
            module=module,
            vuln_type=vuln_type,
            severity=severity,
            confidence=self._get_confidence_label(confidence),
            confidence_score=confidence,
            title=title,
            description=f"Potential {vuln_type} vulnerability detected",
            endpoint=endpoint,
            param=param,
            method=method,
            evidence=evidence,
            remediation=remediation,
            cwe_id=cwe,
            timestamp=datetime.now().isoformat()
        )
        
        self._findings.append(finding)
        
        if self._current_scan:
            self._current_scan.findings.append(finding)
        
        return finding
    
    def _get_confidence_label(self, score: float) -> str:
        if score >= 0.85:
            return "verified"
        elif score >= 0.7:
            return "strong"
        elif score >= 0.5:
            return "moderate"
        elif score >= 0.3:
            return "weak"
        else:
            return "informational"
    
    def add_timeline_event(
        self,
        finding_id: str,
        event_type: str,
        module: str,
        payload_id: str,
        status: str,
        duration_ms: float = 0.0,
        details: Optional[Dict] = None
    ):
        event = ExecutionTimelineEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            module=module,
            payload_id=payload_id,
            status=status,
            duration_ms=duration_ms,
            details=details or {}
        )
        
        self._timeline_cache.append(event)
        
        for finding in self._findings:
            if finding.finding_id == finding_id:
                finding.timeline.append(event)
                break
    
    def end_scan(self, execution_stats: Optional[Dict] = None) -> ScanReport:
        if not self._current_scan:
            return ScanReport()
        
        self._current_scan.end_time = datetime.now().isoformat()
        
        if self._current_scan.start_time:
            start = datetime.fromisoformat(self._current_scan.start_time)
            end = datetime.fromisoformat(self._current_scan.end_time)
            self._current_scan.duration_seconds = (end - start).total_seconds()
        
        self._current_scan.findings = self._findings.copy()
        
        by_severity = {s.value: 0 for s in Severity}
        for finding in self._findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        
        self._current_scan.vulnerabilities_by_severity = by_severity
        
        if execution_stats:
            self._current_scan.execution_stats = execution_stats
        
        return self._current_scan
    
    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self._findings if f.severity == severity]
    
    def get_findings_by_type(self, vuln_type: str) -> List[Finding]:
        return [f for f in self._findings if f.vuln_type == vuln_type]
    
    def get_statistics(self) -> Dict:
        if not self._current_scan:
            return {}
        
        return {
            "total_findings": len(self._findings),
            "by_severity": self._current_scan.vulnerabilities_by_severity,
            "by_type": self._get_findings_by_type(),
            "false_positive_risk": sum(1 for f in self._findings if f.false_positive_likely),
        }
    
    def _get_findings_by_type(self) -> Dict[str, int]:
        by_type = {}
        for f in self._findings:
            by_type[f.vuln_type] = by_type.get(f.vuln_type, 0) + 1
        return by_type
    
    def generate_json_report(self, report: Optional[ScanReport] = None) -> str:
        if report is None:
            report = self._current_scan
        
        if report is None:
            return json.dumps({"error": "No scan report available"})
        
        return json.dumps(report.to_dict(), indent=2)
    
    def generate_markdown_report(self, report: Optional[ScanReport] = None) -> str:
        if report is None:
            report = self._current_scan
        
        if report is None:
            return "# No scan report available\n"
        
        md = []
        md.append(f"# BugHunter AI Elite - Security Scan Report\n")
        md.append(f"**Scan ID:** {report.scan_id}\n")
        md.append(f"**Target:** {report.target}\n")
        md.append(f"**Mode:** {report.mode}\n")
        md.append(f"**Date:** {report.start_time}\n")
        md.append(f"**Duration:** {report.duration_seconds:.2f}s\n")
        md.append(f"\n---\n\n")
        
        md.append(f"## Summary\n\n")
        md.append(f"| Severity | Count |\n")
        md.append(f"|-----------|-------|\n")
        for severity, count in report.vulnerabilities_by_severity.items():
            md.append(f"| {severity.upper()} | {count} |\n")
        
        md.append(f"\n**Total Findings:** {len(report.findings)}\n")
        md.append(f"\n---\n\n")
        
        if report.findings:
            md.append(f"## Findings\n\n")
            
            for i, finding in enumerate(report.findings, 1):
                md.append(f"### {i}. {finding.title}\n")
                md.append(f"**Severity:** {finding.severity.upper()}\n")
                md.append(f"**Confidence:** {finding.confidence} ({finding.confidence_score:.0%})\n")
                md.append(f"**Endpoint:** `{finding.method} {finding.endpoint}`\n")
                md.append(f"**Parameter:** `{finding.param}`\n")
                
                if finding.cwe_id:
                    md.append(f"**CWE:** {finding.cwe_id}\n")
                
                md.append(f"\n**Description:**\n{finding.description}\n")
                
                if finding.evidence.payload:
                    md.append(f"\n**Payload:**\n```\n{finding.evidence.payload}\n```\n")
                
                if finding.evidence.response_snippet:
                    md.append(f"\n**Evidence:**\n{finding.evidence.response_snippet}\n")
                
                md.append(f"\n**Remediation:**\n{finding.remediation}\n")
                md.append(f"\n---\n\n")
        
        return "".join(md)
    
    def generate_terminal_summary(self, report: Optional[ScanReport] = None) -> str:
        if report is None:
            report = self._current_scan
        
        if report is None:
            return "No scan report available"
        
        lines = []
        lines.append("=" * 60)
        lines.append(f"BUGHunter AI Elite - Scan Report")
        lines.append("=" * 60)
        lines.append(f"Scan ID: {report.scan_id}")
        lines.append(f"Target: {report.target}")
        lines.append(f"Mode: {report.mode}")
        lines.append(f"Duration: {report.duration_seconds:.2f}s")
        lines.append("-" * 60)
        
        severity_colors = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO"
        }
        
        lines.append("\nFindings by Severity:")
        for severity, count in report.vulnerabilities_by_severity.items():
            color = severity_colors.get(severity, severity.upper())
            lines.append(f"  [{color}] {severity.upper()}: {count}")
        
        lines.append(f"\nTotal Findings: {len(report.findings)}")
        
        if report.findings:
            lines.append("\n" + "-" * 60)
            lines.append("FINDINGS:")
            lines.append("-" * 60)
            
            for i, f in enumerate(report.findings[:20], 1):
                severity_marker = f.severity[0].upper()
                lines.append(f"{i}. [{severity_marker}] {f.vuln_type} @ {f.endpoint}?{f.param}")
                lines.append(f"   Confidence: {f.confidence} ({f.confidence_score:.0%})")
                if f.cwe_id:
                    lines.append(f"   {f.cwe_id}")
                lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def get_latest_report(self) -> Optional[ScanReport]:
        return self._current_scan
    
    def clear_findings(self):
        self._findings = []
        self._finding_counter = 0


_reporting_instance: Optional[ReportingEngine] = None


def get_reporting_engine(config: Optional[Dict] = None) -> ReportingEngine:
    global _reporting_instance
    
    if _reporting_instance is None:
        _reporting_instance = ReportingEngine(config)
    
    return _reporting_instance


def reset_reporting_engine():
    global _reporting_instance
    _reporting_instance = None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("\n=== Reporting Engine Test ===\n")
    
    engine = get_reporting_engine()
    
    report = engine.start_scan("SCAN-00001", "https://example.com", "bb_mode")
    
    engine.create_finding(
        scan_id=report.scan_id,
        module="xss",
        vuln_type="xss",
        endpoint="https://example.com/login",
        param="username",
        payload="<script>alert(1)</script>",
        payload_id="xss_bas_001",
        response_snippet="<script>alert(1)</script>",
        severity="medium",
        confidence=0.75
    )
    
    engine.create_finding(
        scan_id=report.scan_id,
        module="sqli",
        vuln_type="sqli",
        endpoint="https://example.com/user",
        param="id",
        payload="' OR '1'='1",
        payload_id="sqli_bas_001",
        response_snippet="MySQL syntax error",
        severity="high",
        confidence=0.85
    )
    
    stats = {"total_requests": 150, "total_payloads": 500}
    final_report = engine.end_scan(stats)
    
    print("=== Terminal Summary ===\n")
    print(engine.generate_terminal_summary(final_report))
    
    print("\n=== JSON Summary ===")
    summary = engine.get_statistics()
    print(f"Total: {summary['total_findings']}")
    print(f"By severity: {summary['by_severity']}")
    print(f"By type: {summary['by_type']}")