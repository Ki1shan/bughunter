import json
import re
from datetime import datetime


class EnhancedScoringEngine:
    def __init__(self, knowledge_base):
        self.kb = knowledge_base
        
        self.base_weights = {
            "response_changes": 3,
            "anomaly_detected": 2,
            "sensitive_param": 2,
            "reflection": 1,
            "status_code_change": 2,
            "high_confidence": 2,
            "medium_confidence": 1,
            "chain_bonus": 3,
            "critical_severity": 4,
            "high_severity": 3,
            "js_discovered": 1,
            "auth_required": 1,
            "sensitive_data": 2
        }
        
        self.sensitive_params = [
            "id", "user_id", "uid", "uuid", "account_id", "token", "auth",
            "password", "secret", "key", "api_key", "apikey", "session",
            "admin", "role", "privilege", "email", "phone", "address",
            "credit_card", "ssn", "dob", "card", "cvv", "balance",
            "payment", "order", "transaction"
        ]
        
        self.critical_params = [
            "id", "user_id", "admin", "role", "privilege", "token", "auth",
            "password", "secret", "api_key"
        ]
        
        self.anomaly_weights = {
            "status_change": 2.5,
            "response_diff": 2.0,
            "timing_delay": 1.5,
            "error_keyword": 2.0,
            "exposed_env_file": 3.0,
            "exposed_git": 2.5,
            "stack_trace": 2.5,
            "csp_header": -1.0
        }
        
        self.severity_multipliers = {
            "critical": 1.5,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.8
        }
    
    def analyze_param_context(self, param_name):
        context_score = 0
        
        param_lower = param_name.lower()
        
        if any(c in param_lower for c in self.critical_params):
            context_score += 3
            
        if any(s in param_lower for s in self.sensitive_params):
            context_score += 2
            
        if any(x in param_lower for x in ["id", "_id"]):
            context_score += 2
            
        if any(x in param_lower for x in ["search", "query", "term"]):
            context_score += 1
            
        if any(x in param_lower for x in ["file", "path", "url"]):
            context_score += 2
            
        if any(x in param_lower for x in ["redirect", "next", "return"]):
            context_score += 2
            
        return context_score
    
    def calculate_chaining_impact(self, chain_results):
        impact_score = 0
        
        chains = chain_results.get("chains", [])
        for chain in chains:
            severity = chain.get("severity", "low")
            impact_score += self.severity_multipliers.get(severity, 1.0) * self.base_weights["chain_bonus"]
            
        return impact_score
    
    def apply_confidence_modifier(self, base_score, logic_findings, heuristic_findings):
        high_conf_count = sum(1 for f in logic_findings if f.get("confidence") == "high")
        medium_conf_count = sum(1 for f in logic_findings if f.get("confidence") == "medium")
        
        high_anomaly = sum(1 for a in heuristic_findings if a.get("confidence") == "high")
        
        total_indicators = high_conf_count + medium_conf_count + high_anomaly
        
        if total_indicators >= 3:
            return base_score * 1.3
        elif total_indicators >= 2:
            return base_score * 1.15
        elif total_indicators >= 1:
            return base_score * 1.05
            
        return base_score
    
    def calculate_score(self, endpoint, logic_findings, heuristic_findings, chain_results=None, fast_mode=False):
        score = 0
        
        params = endpoint.get("params", [])
        
        for param in params:
            context_score = self.analyze_param_context(param)
            score += min(context_score, 5)
        
        for finding in logic_findings:
            finding_type = finding.get("type", "")
            
            type_mapping = {
                "sqli": "sql_injection",
                "cmdi": "command_injection",
                "path_traversal": "lfi",
                "xxe": "xml_injection",
                "race_conditions": "race_condition"
            }
            finding_type = type_mapping.get(finding_type, finding_type)
            
            if self.kb.get(finding_type):
                kb_severity = self.kb[finding_type].get("severity", "low")
                severity_mult = self.severity_multipliers.get(kb_severity, 1.0)
                
                validation_status = finding.get("validation_status", "")
                if validation_status == "skipped (param-based only)":
                    continue
                
                tier_multiplier = 1.0
                if fast_mode:
                    conf = finding.get("confidence", "low")
                    if conf == "high":
                        tier_multiplier = 0.8
                    elif conf == "medium":
                        tier_multiplier = 0.5
                    else:
                        tier_multiplier = 0.3
                elif validation_status == "confirmed":
                    tier_multiplier = 1.0
                elif validation_status == "likely":
                    tier_multiplier = 0.5
                else:
                    tier_multiplier = 0.2
                
                if "response changes" in finding.get("reason", "").lower():
                    score += self.base_weights["response_changes"] * severity_mult * tier_multiplier
                elif "reflection" in finding.get("reason", "").lower():
                    score += self.base_weights["reflection"] * severity_mult * tier_multiplier
                    
                conf = finding.get("confidence", "low")
                if conf == "high":
                    score += self.base_weights["high_confidence"] * severity_mult * tier_multiplier
                elif conf == "medium":
                    score += self.base_weights["medium_confidence"] * severity_mult * tier_multiplier
        
        for anomaly in heuristic_findings:
            anomaly_type = anomaly.get("type", "")
            weight = self.anomaly_weights.get(anomaly_type, 1.0)
            score += weight
        
        confirmed_count = sum(1 for f in logic_findings if f.get("validation_status") == "confirmed")
        likely_count = sum(1 for f in logic_findings if f.get("validation_status") == "likely")
        skipped_count = sum(1 for f in logic_findings if "skipped" in str(f.get("validation_status", "")))
        effective_confirmed = confirmed_count + (likely_count * 0.5)
        
        total_findings = len(logic_findings)
        status_code = endpoint.get("status_code", 200)
        is_dead_endpoint = status_code in (404, 405, 503) and total_findings == 0
        
        if is_dead_endpoint:
            score = min(score * 0.1, 0.5)
        elif total_findings > 0 and effective_confirmed == 0 and not fast_mode:
            score = min(score * 0.2, 1.5)
            for anomaly in heuristic_findings:
                if anomaly.get("type") in ["error_keyword", "config_keyword", "password_keyword", "token_keyword", "debug_mode"]:
                    score -= self.anomaly_weights.get(anomaly.get("type"), 1.0)
            score = max(score, 0)
        elif effective_confirmed < total_findings * 0.3 and not fast_mode:
            score = score * 0.5
        
        total_confidence = (len(logic_findings) + len(heuristic_findings)) / max(len(params), 1)
        if total_confidence > 3:
            score *= 1.2
        
        if endpoint.get("source") == "js_discovery":
            score += self.base_weights["js_discovered"]
            
        if endpoint.get("js_tokens"):
            score += self.base_weights["sensitive_data"]
        
        if chain_results and chain_results.get("chains"):
            chain_impact = self.calculate_chaining_impact(chain_results)
            score += chain_impact
        
        score = self.apply_confidence_modifier(score, logic_findings, heuristic_findings)
        
        return min(int(score * 10) / 10, 20)
    
    def get_severity(self, score):
        if score >= 10:
            return "critical"
        elif score >= 7:
            return "high"
        elif score >= 4:
            return "medium"
        else:
            return "low"
    
    def get_confidence(self, logic_findings, heuristic_findings, score):
        high_conf = sum(1 for f in logic_findings if f.get("confidence") == "high")
        med_conf = sum(1 for f in logic_findings if f.get("confidence") == "medium")
        high_anom = sum(1 for a in heuristic_findings if a.get("confidence") == "high")
        
        if high_conf >= 2 or (high_conf >= 1 and high_anom >= 1) or score >= 8:
            return "high"
        elif high_conf >= 1 or high_anom >= 1 or score >= 5:
            return "medium"
        else:
            return "low"
    
    def calculate(self, endpoint, logic_findings, heuristic_findings, chain_results=None, fast_mode=False):
        score = self.calculate_score(endpoint, logic_findings, heuristic_findings, chain_results, fast_mode)
        
        result = {
            "score": score,
            "severity": self.get_severity(score),
            "confidence": self.get_confidence(logic_findings, heuristic_findings, score),
            "factors": {
                "logic_findings_count": len(logic_findings),
                "heuristic_findings_count": len(heuristic_findings),
                "params_count": len(endpoint.get("params", [])),
                "chain_count": len(chain_results.get("chains", [])) if chain_results else 0
            }
        }
        
        return result


def calculate_score(endpoint, logic_findings, heuristic_findings, chain_results=None, fast_mode=False):
    with open("knowledge_base.json", "r") as f:
        kb = json.load(f)
    
    engine = EnhancedScoringEngine(kb)
    return engine.calculate(endpoint, logic_findings, heuristic_findings, chain_results, fast_mode)