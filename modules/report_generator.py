import json
from datetime import datetime
from modules.logging_config import logger


class ReportGenerator:
    def __init__(self, config, knowledge_base):
        self.config = config
        self.kb = knowledge_base
        self.output_dir = config.get("output_dir", "output")
        
    def generate_endpoint_report(self, endpoint, logic_findings, heuristic_findings, 
                                  score_results, chain_results, ai_results, scripts):
        severity = score_results.get("severity", "low")
        
        issue_details = []
        for finding in logic_findings:
            vtype = finding.get("type", "unknown")
            
            type_mapping = {
                "sqli": "sql_injection",
                "cmdi": "command_injection",
                "path_traversal": "lfi",
                "xxe": "xml_injection",
                "race_conditions": "race_condition"
            }
            vtype = type_mapping.get(vtype, vtype)
            
            kb_info = self.kb.get(vtype, {})
            issue = {
                "type": vtype,
                "param": finding.get("param"),
                "reason": finding.get("reason"),
                "confidence": finding.get("confidence"),
                "impact": kb_info.get("impact", "Unknown"),
                "severity": kb_info.get("severity", "unknown"),
                "validation_status": finding.get("validation_status", "not_validated")
            }
            issue_details.append(issue)
        
        report = {
            "endpoint": endpoint["url"],
            "method": endpoint.get("method", "GET"),
            "parameters": endpoint.get("params", []),
            "timestamp": datetime.now().isoformat(),
            "scan_results": {
                "issues": issue_details,
                "anomalies": heuristic_findings,
                "chains": chain_results.get("chains", []),
                "attack_chains": chain_results.get("attack_chains", []),
                "score": score_results.get("score"),
                "severity": severity,
                "confidence": score_results.get("confidence"),
                "factors": score_results.get("factors", {})
            },
            "ai_analysis": {
                "analysis": ai_results.get("ai_analysis"),
                "error": ai_results.get("ai_error"),
                "model": ai_results.get("model_used"),
                "tokens": ai_results.get("tokens_used")
            },
            "generated_scripts": list(scripts.keys()),
            "recommended_tests": self._get_recommended_tests(logic_findings)
        }
        
        return report
    
    def _get_recommended_tests(self, findings):
        tests = []
        for finding in findings:
            vtype = finding.get("type")
            if vtype in self.kb:
                tests.extend(self.kb[vtype].get("tests", []))
        return list(set(tests))[:10]
    
    def generate_summary_report(self, all_results):
        total_endpoints = len(all_results)
        
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        issue_types = {}
        total_chains = 0
        
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
        
        for result in all_results:
            max_severity = "low"
            for issue in result.get("scan_results", {}).get("issues", []):
                vtype = issue.get("type", "unknown")
                issue_types[vtype] = issue_types.get(vtype, 0) + 1
                
                issue_sev = issue.get("severity", "low").lower()
                if severity_order.get(issue_sev, 0) > severity_order.get(max_severity, 0):
                    max_severity = issue_sev
                    
            total_chains += len(result.get("scan_results", {}).get("chains", []))
            total_chains += len(result.get("scan_results", {}).get("attack_chains", []))
            
            if max_severity in severity_counts:
                severity_counts[max_severity] += 1
        
        return {
            "scan_summary": {
                "total_endpoints_scanned": total_endpoints,
                "critical_issues": severity_counts["critical"],
                "high_issues": severity_counts["high"],
                "medium_issues": severity_counts["medium"],
                "low_issues": severity_counts["low"],
                "total_chains": total_chains
            },
            "issue_breakdown": issue_types,
            "timestamp": datetime.now().isoformat()
        }
    
    def save_report(self, report, filename=None):
        if not filename:
            filename = f"bughunter_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
        filepath = f"{self.output_dir}/{filename}"
        
        try:
            with open(filepath, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Report save error: {e}")
            return None
    
    def generate_html_report(self, results, summary):
        severity_colors = {
            "critical": "#ff4444",
            "high": "#ff8844",
            "medium": "#ffbb33",
            "low": "#44cc44",
        }
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugHunter AI - Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #0a0a0f, #1a1a2e); padding: 30px 40px; border-bottom: 1px solid #2a2a3a; }}
        .header h1 {{ font-size: 28px; background: linear-gradient(90deg, #00ff88, #00ffaa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .header p {{ color: #888; margin-top: 5px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; padding: 30px 40px; }}
        .stat-box {{ background: #12121a; padding: 20px; border-radius: 12px; text-align: center; border: 1px solid #2a2a3a; }}
        .stat-box .label {{ font-size: 12px; color: #888; text-transform: uppercase; letter-spacing: 1px; }}
        .stat-box .value {{ font-size: 36px; font-weight: bold; margin-top: 8px; }}
        .critical .value {{ color: #ff4444; }} .high .value {{ color: #ff8844; }}
        .medium .value {{ color: #ffbb33; }} .low .value {{ color: #44cc44; }}
        .section {{ padding: 20px 40px; }}
        .section-title {{ font-size: 20px; font-weight: 600; margin-bottom: 20px; padding-left: 16px; border-left: 4px solid #00ff88; }}
        .endpoint {{ background: #12121a; margin: 16px 0; padding: 20px; border-radius: 12px; border: 1px solid #2a2a3a; }}
        .endpoint-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }}
        .endpoint-url {{ font-family: 'Consolas', monospace; font-size: 14px; color: #88ccff; }}
        .endpoint-meta {{ font-size: 13px; color: #888; }}
        .issue {{ padding: 12px 16px; margin: 8px 0; border-radius: 8px; border-left: 4px solid #666; background: #1a1a25; }}
        .issue.critical {{ border-color: #ff4444; background: rgba(255,68,68,0.08); }}
        .issue.high {{ border-color: #ff8844; background: rgba(255,136,68,0.08); }}
        .issue.medium {{ border-color: #ffbb33; background: rgba(255,187,51,0.08); }}
        .issue.low {{ border-color: #44cc44; background: rgba(68,204,68,0.08); }}
        .issue-type {{ font-weight: 600; text-transform: uppercase; }}
        .issue-detail {{ font-size: 13px; color: #888; margin-top: 4px; }}
        .severity-badge {{ padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
        .severity-badge.critical {{ background: #ff4444; color: #fff; }}
        .severity-badge.high {{ background: #ff8844; color: #000; }}
        .severity-badge.medium {{ background: #ffbb33; color: #000; }}
        .severity-badge.low {{ background: #44cc44; color: #000; }}
        .chain {{ padding: 16px; margin: 12px 0; border-radius: 8px; background: #1a1a25; border: 1px solid #2a2a3a; }}
        .chain-path {{ font-family: 'Consolas', monospace; color: #00ff88; font-size: 14px; padding: 10px; background: rgba(0,255,136,0.05); border-radius: 6px; }}
        .footer {{ text-align: center; padding: 40px; color: #888; font-size: 13px; border-top: 1px solid #2a2a3a; margin-top: 40px; }}
        @media (max-width: 768px) {{ .summary {{ grid-template-columns: repeat(2, 1fr); }} }}
    </style>
</head>
<body>
    <div class="header">
        <h1>BugHunter AI - Security Analysis Report</h1>
        <p>Generated: {summary.get('timestamp', '')}</p>
    </div>
    
    <div class="summary">
        <div class="stat-box">
            <div class="label">Endpoints</div>
            <div class="value">{summary['scan_summary']['total_endpoints_scanned']}</div>
        </div>
        <div class="stat-box critical">
            <div class="label">Critical</div>
            <div class="value">{summary['scan_summary']['critical_issues']}</div>
        </div>
        <div class="stat-box high">
            <div class="label">High</div>
            <div class="value">{summary['scan_summary']['high_issues']}</div>
        </div>
        <div class="stat-box medium">
            <div class="label">Medium</div>
            <div class="value">{summary['scan_summary']['medium_issues']}</div>
        </div>
        <div class="stat-box low">
            <div class="label">Low</div>
            <div class="value">{summary['scan_summary']['low_issues']}</div>
        </div>
    </div>
    
    <div class="section">
        <div class="section-title">Detailed Findings</div>
"""
        
        for result in results:
            severity = result.get("scan_results", {}).get("severity", "low")
            issues = result.get("scan_results", {}).get("issues", [])
            score = result.get("scan_results", {}).get("score", 0)
            
            html += f"""
        <div class="endpoint">
            <div class="endpoint-header">
                <span class="endpoint-url">{result.get('method', 'GET')} {result.get('endpoint', 'Unknown')}</span>
                <div>
                    <span class="severity-badge {severity}">{severity}</span>
                    <span style="color:#888; margin-left:10px;">Score: {score}</span>
                </div>
            </div>
"""
            
            for issue in issues:
                issue_severity = issue.get("severity", "low")
                html += f"""
            <div class="issue {issue_severity}">
                <span class="issue-type">{issue.get('type', 'unknown')}</span>
                <div class="issue-detail">
                    Parameter: {issue.get('param', 'N/A')} | 
                    Confidence: {issue.get('confidence', 'N/A')} | 
                    Status: {issue.get('validation_status', 'N/A')}
                </div>
                <div class="issue-detail">{issue.get('reason', '')}</div>
            </div>
"""
            
            chains = result.get("scan_results", {}).get("chains", [])
            attack_chains = result.get("scan_results", {}).get("attack_chains", [])
            all_chains = chains + attack_chains
            
            if all_chains:
                html += f"""
            <div style="margin-top:16px;">
                <strong style="color:#00ff88;">Attack Chains ({len(all_chains)})</strong>
"""
                for chain in all_chains:
                    name = chain.get("name", chain.get("chain_name", "Unknown"))
                    chain_severity = chain.get("severity", "low")
                    steps = chain.get("steps", [])
                    step_labels = [s.get("action", s.get("vuln_type", "?")) for s in steps]
                    path = " &rarr; ".join(step_labels)
                    
                    html += f"""
                <div class="chain">
                    <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
                        <span><span class="severity-badge {chain_severity}">{chain_severity}</span> {name}</span>
                        <span style="color:#888;">Score: {chain.get('impact_score', chain.get('score', 0)):.1f}</span>
                    </div>
                    <div class="chain-path">{path}</div>
                </div>
"""
                html += "</div>"
            
            html += "</div>"
        
        html += """
    </div>
    
    <div class="footer">
        Generated by BugHunter AI v2.0 | Advanced Security Analysis Engine
    </div>
</body>
</html>"""
        
        return html


def generate_report(config, knowledge_base, endpoint, logic_findings, heuristic_findings, 
                    score_results, chain_results, ai_results, scripts):
    generator = ReportGenerator(config, knowledge_base)
    return generator.generate_endpoint_report(
        endpoint, logic_findings, heuristic_findings, 
        score_results, chain_results, ai_results, scripts
    )
