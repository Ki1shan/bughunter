import json
from modules.logging_config import logger


class VulnerabilityChainingEngine:
    def __init__(self, knowledge_base):
        self.kb = knowledge_base
    
    def chain_findings(self, findings, anomalies, score_results):
        chains = []
        
        issue_types = [f.get("type") for f in findings]
        
        if "idor" in issue_types and "status_change" in [a.get("type") for a in anomalies]:
            chains.append({
                "chain": ["idor", "status_change"],
                "name": "IDOR with Bypass Potential",
                "description": "IDOR vulnerability combined with access control bypass indicators",
                "severity": "critical",
                "attack_path": [
                    "1. Identify user-specific parameter (id, user_id)",
                    "2. Modify parameter to access other users' data",
                    "3. Check if status change reveals access control issues"
                ]
            })
        
        if "xss" in issue_types and not any(a.get("type") == "csp_header" for a in anomalies):
            chains.append({
                "chain": ["xss", "no_csp"],
                "name": "XSS without CSP Protection",
                "description": "Reflected XSS without Content Security Policy protection",
                "severity": "high",
                "attack_path": [
                    "1. Confirm XSS vector in parameter",
                    "2. Test various bypass techniques",
                    "3. Execute payload to steal cookies/tokens"
                ]
            })
        
        if "sql_injection" in issue_types and "timing_delay" in [a.get("type") for a in anomalies]:
            chains.append({
                "chain": ["sql_injection", "blind_injection"],
                "name": "Blind SQL Injection",
                "description": "SQL injection with time-based blind extraction",
                "severity": "critical",
                "attack_path": [
                    "1. Confirm SQL injection in parameter",
                    "2. Use time-based payloads for blind extraction",
                    "3. Extract data via conditional responses"
                ]
            })
        
        if "idor" in issue_types:
            idor_findings = [f for f in findings if f.get("type") == "idor"]
            
            idor_with_privilege = {
                "chain": ["idor", "privilege_escalation"],
                "name": "IDOR leading to Privilege Escalation",
                "description": "Attempt to escalate privileges via IDOR",
                "severity": "high",
                "attack_path": [
                    "1. Access own user profile/resources",
                    "2. Modify user_id or role parameter to admin values",
                    "3. Access admin functionality"
                ]
            }
            chains.append(idor_with_privilege)
        
        if "open_redirect" in issue_types and "xss" in issue_types:
            chains.append({
                "chain": ["open_redirect", "xss"],
                "name": "Open Redirect with XSS Chaining",
                "description": "Chain open redirect for phishing with XSS for session hijacking",
                "severity": "medium",
                "attack_path": [
                    "1. Identify open redirect parameter",
                    "2. Use redirect to initial phishing page",
                    "3. Use XSS to steal credentials"
                ]
            })
        
        if score_results.get("severity") in ["high", "critical"]:
            severe_issue = None
            for f in findings:
                kb_entry = self.kb.get(f.get("type", ""))
                if kb_entry and kb_entry.get("severity") == "critical":
                    severe_issue = f
                    break
            
            if severe_issue and any(a.get("type") == "error_keyword" for a in anomalies):
                chains.append({
                    "chain": [severe_issue.get("type"), "information_disclosure"],
                    "name": f"Chained: {severe_issue.get('type').upper()} + Info Disclosure",
                    "description": "Critical vulnerability with information disclosure",
                    "severity": "critical",
                    "attack_path": [
                        f"1. Exploit {severe_issue.get('type')} vulnerability",
                        "2. Leverage info disclosure for further access",
                        "3. Escalate access"
                    ]
                })
        
        unique_chains = []
        seen_chains = set()
        for chain in chains:
            chain_key = "-".join(chain.get("chain", []))
            if chain_key not in seen_chains:
                seen_chains.add(chain_key)
                unique_chains.append(chain)
        
        return unique_chains
    
    def escalate_severity(self, original_severity, chain_length):
        severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        
        original_level = severity_levels.get(original_severity, 0)
        escalation = min(original_level + chain_length - 1, 3)
        
        return list(severity_levels.keys())[escalation]
    
    def process_all_findings(self, logic_findings, heuristic_findings, score_results):
        chains = self.chain_findings(logic_findings, heuristic_findings, score_results)
        
        return {
            "chains": chains,
            "total_chains": len(chains),
            "highest_severity": max([c.get("severity", "low") for c in chains], 
                                   key=lambda x: {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(x, 0)) if chains else score_results.get("severity", "low")
        }


def chain_vulnerabilities(knowledge_base, logic_findings, heuristic_findings, score_results):
    engine = VulnerabilityChainingEngine(knowledge_base)
    return engine.process_all_findings(logic_findings, heuristic_findings, score_results)