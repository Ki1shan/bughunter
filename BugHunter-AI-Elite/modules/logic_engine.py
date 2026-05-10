import json
import re
import httpx
from urllib.parse import urlparse, parse_qs
from modules.logging_config import logger
from modules.vuln_validator import VulnerabilityValidator


class LogicEngine:
    def __init__(self, config, knowledge_base):
        self.config = config
        self.kb = knowledge_base
        self.user_agent = config.get("user_agent", "BugHunter-AI/v1.0")
        self.timeout = config.get("request_timeout", 10)
        
    async def check_idor(self, endpoint, profile):
        findings = []
        validator = VulnerabilityValidator(self.config, self.kb)
        
        id_params = ["id", "user_id", "uid", "uuid", "account_id", "post_id", "order_id", "item_id"]
        
        for param in endpoint.get("params", []):
            if any(idp in param.lower() for idp in id_params):
                findings.append({
                    "type": "idor",
                    "param": param,
                    "reason": "ID-like parameter present",
                    "confidence": "medium"
                })
                
                for test in profile.get("tests", []):
                    if test["param"] == param and test.get("differences", {}).get("content_diff"):
                        test_response = {"text": test.get("response", ""), "status_code": test.get("status", 0)}
                        baseline_response = profile.get("baseline", {})
                        validated = validator.validate_response(baseline_response, test_response, "idor")
                        if validated.get("confirmed"):
                            findings.append({
                                "type": "idor",
                                "param": param,
                                "reason": "Response changes with parameter modification",
                                "confidence": "high",
                                "validated": True
                            })
                            break
        
        return findings
    
    async def check_xss(self, endpoint, profile):
        findings = []
        validator = VulnerabilityValidator(self.config, self.kb)
        
        if not endpoint.get("params"):
            return findings
            
        baseline = profile.get("baseline", {})
        
        for test in profile.get("tests", []):
            payload = test.get("payload", "")
            differences = test.get("differences", {})
            
            test_response = {"text": test.get("response", ""), "status_code": test.get("status", 0)}
            baseline_response = {"text": profile.get("baseline", {}).get("text", ""), "status_code": profile.get("baseline", {}).get("status_code", 0)}
            
            special_chars = ["<", ">", "'", "\"", "script", "javascript", "onerror", "onload"]
            has_special = any(char in payload for char in special_chars)
            
            if has_special and differences.get("content_diff"):
                validated = validator.validate_response(baseline_response, test_response, "xss", payload)
                if validated.get("confirmed"):
                    matched_chars = [char for char in special_chars if char in payload and char in test.get("response", "")]
                    findings.append({
                        "type": "xss",
                        "param": test["param"],
                        "reason": f"Special characters ({', '.join(matched_chars[:3])}) reflected with response change",
                        "confidence": "medium",
                        "validated": True
                    })
        
        return findings
    
    async def check_sql_injection(self, endpoint, profile):
        findings = []
        validator = VulnerabilityValidator(self.config, self.kb)
        
        sql_errors = [
            "sql syntax", "mysql", "postgresql", "ora-", "sqlserver",
            "unterminated", "quoted string", "syntax error", "warning:",
            "mysql_fetch", "oci", "odbc"
        ]
        
        for test in profile.get("tests", []):
            payload = test.get("payload", "")
            if any(sql_str in payload.lower() for sql_str in ["'", "union", "select", "--", "sleep"]):
                test_text = test.get("response", "").lower()
                differences = test.get("differences", {})
                
                for error in sql_errors:
                    if error in test_text and error not in profile.get("baseline", {}).get("text", "").lower():
                        test_response = {"text": test.get("response", ""), "status_code": test.get("status", 0)}
                        baseline_response = {"text": profile.get("baseline", {}).get("text", ""), "status_code": profile.get("baseline", {}).get("status_code", 0)}
                        validated = validator.validate_response(baseline_response, test_response, "sqli", payload)
                        if validated.get("confirmed"):
                            findings.append({
                                "type": "sql_injection",
                                "param": test.get("param"),
                                "reason": f"SQL error pattern '{error}' found in test response only",
                                "confidence": "high",
                                "validated": True
                            })
                        break
                
                if not findings and (differences.get("status_change") or differences.get("length_diff")):
                    test_response = {"text": test.get("response", ""), "status_code": test.get("status", 0)}
                    baseline_response = {"text": profile.get("baseline", {}).get("text", ""), "status_code": profile.get("baseline", {}).get("status_code", 0)}
                    validated = validator.validate_response(baseline_response, test_response, "sqli", payload)
                    if validated.get("confirmed"):
                        findings.append({
                            "type": "sql_injection",
                            "param": test.get("param"),
                            "reason": "SQL injection payload causes response change",
                            "confidence": "medium",
                            "validated": True
                        })
        
        return findings
    
    async def check_ssrf(self, endpoint):
        findings = []
        
        ssrf_params = ["url", "redirect", "fetch", "load", "src", "dest", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir", "show", "navigation", "open", "file", "document", "folder", "pg", "style", "doc", "img", "source", "target", "c", "pageid", "name", "m", "ref", "search_theme", "activity", "widget", "text", "fullpath", "prefix"]
        
        for param in endpoint.get("params", []):
            if any(ssrf in param.lower() for ssrf in ssrf_params):
                findings.append({
                    "type": "ssrf",
                    "param": param,
                    "reason": "Potential SSRF parameter",
                    "confidence": "low"
                })
        
        return findings
    
    async def check_open_redirect(self, endpoint, profile):
        findings = []
        
        redirect_params = ["redirect", "url", "next", "return", "goto", "target", "dest", "callback", "redirect_uri", "return_url", "continue", "out", "view"]
        
        for param in endpoint.get("params", []):
            if any(rp in param.lower() for rp in redirect_params):
                findings.append({
                    "type": "open_redirect",
                    "param": param,
                    "reason": "Potential redirect parameter",
                    "confidence": "low"
                })
                
                for test in profile.get("tests", []):
                    if test["param"] == param:
                        payload = test.get("payload", "")
                        if payload.startswith("http") or payload.startswith("//") or payload.startswith("javascript:"):
                            findings.append({
                                "type": "open_redirect",
                                "param": param,
                                "reason": f"Suspicious redirect payload: {payload[:20]}",
                                "confidence": "medium"
                            })
        
        return findings
    
    async def analyze_endpoint(self, endpoint, profile):
        all_findings = []
        
        all_findings.extend(await self.check_idor(endpoint, profile))
        all_findings.extend(await self.check_xss(endpoint, profile))
        all_findings.extend(await self.check_sql_injection(endpoint, profile))
        all_findings.extend(await self.check_ssrf(endpoint))
        all_findings.extend(await self.check_open_redirect(endpoint, profile))
        
        unique_findings = []
        seen = set()
        for f in all_findings:
            key = f"{f.get('type')}-{f.get('param', '')}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        
        return unique_findings


async def run_logic_engine(config, knowledge_base, endpoint, profile):
    engine = LogicEngine(config, knowledge_base)
    return await engine.analyze_endpoint(endpoint, profile)