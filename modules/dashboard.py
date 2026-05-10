import json
from datetime import datetime
from pathlib import Path


def generate_dashboard_data(scan_results, attack_surface, summary):
    data = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "target": scan_results.get("target", "Unknown"),
            "duration": scan_results.get("duration", 0)
        },
        "summary": summary.get("scan_summary", {}),
        "severity_breakdown": {
            "critical": summary.get("scan_summary", {}).get("critical_issues", 0),
            "high": summary.get("scan_summary", {}).get("high_issues", 0),
            "medium": summary.get("scan_summary", {}).get("medium_issues", 0),
            "low": summary.get("scan_summary", {}).get("low_issues", 0)
        },
        "attack_surface": {
            "endpoints": summary.get("scan_summary", {}).get("total_endpoints_scanned", 0),
            "subdomains": len(attack_surface.get("subdomains", [])),
            "api_endpoints": len(attack_surface.get("api_endpoints", [])),
            "hidden_routes": len(attack_surface.get("hidden_routes", [])),
            "js_discovered": len(attack_surface.get("js_discovered", []))
        },
        "vulnerability_types": summary.get("issue_breakdown", {}),
        "chains": summary.get("scan_summary", {}).get("total_chains", 0),
        "findings": scan_results.get("findings", [])
    }
    return data


def _collect_chains(findings_list):
    chains = []
    for f in findings_list:
        scan = f.get("scan_results", {})
        for c in scan.get("chains", []):
            chains.append({
                "endpoint": f.get("endpoint", ""),
                "name": c.get("name", ""),
                "severity": c.get("severity", "low"),
                "score": c.get("impact_score", 0),
                "probability": c.get("chain_probability", 0),
                "cvss": c.get("cvss_estimate", ""),
                "business_impact": c.get("business_impact", ""),
                "remediation": c.get("remediation_priority", ""),
                "steps": c.get("steps", []),
                "real_world": c.get("real_world_example", ""),
            })
        for c in scan.get("attack_chains", []):
            chains.append({
                "endpoint": f.get("endpoint", ""),
                "name": c.get("name", ""),
                "severity": c.get("severity", "low"),
                "score": c.get("score", 0),
                "probability": c.get("probability", 0),
                "cvss": c.get("cvss", ""),
                "business_impact": c.get("impact", ""),
                "remediation": "",
                "steps": c.get("steps", []),
                "real_world": "",
            })
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    chains.sort(key=lambda c: (severity_order.get(c["severity"], 4), -c["score"]))
    return chains


def _chain_html(chains):
    if not chains:
        return '<div class="empty-state">No attack chains detected</div>'

    html = ""
    for c in chains:
        steps = c["steps"]
        step_labels = []
        for s in steps:
            label = s.get("action", s.get("vuln_type", "?"))
            step_labels.append(label)

        path_display = " &rarr; ".join(step_labels)
        steps_detail = ""
        for s in steps:
            steps_detail += f"""
            <div class="chain-step">
                <span class="chain-step-num">{s.get('step', '?')}</span>
                <span class="chain-step-action">{s.get('action', '')}</span>
                <span class="chain-step-desc">{s.get('description', '')}</span>
            </div>"""

        sev = c["severity"]
        html += f"""
        <div class="chain-card {sev}">
            <div class="chain-header">
                <div>
                    <span class="severity-badge {sev}">{sev.upper()}</span>
                    <span class="chain-name">{c['name']}</span>
                </div>
                <div class="chain-meta">
                    <span class="chain-score">Score: {c['score']:.1f}</span>
                    <span class="chain-prob">Prob: {c['probability']:.0%}</span>
                    {f'<span class="chain-cvss">CVSS: {c["cvss"]}</span>' if c.get('cvss') else ''}
                </div>
            </div>
            <div class="chain-path">{path_display}</div>
            <div class="chain-steps">{steps_detail}</div>
            <div class="chain-impact">
                <strong>Impact:</strong> {c['business_impact']}
            </div>
            <div class="chain-endpoint">
                <span class="chain-ep-label">Endpoint:</span> {c['endpoint']}
            </div>
        </div>"""

    return html


def generate_standalone_dashboard(scan_results, attack_surface, summary):
    scan_summary = summary.get('scan_summary', {})
    issue_breakdown = summary.get('issue_breakdown', {})
    findings_list = scan_results.get('findings', [])
    subdomains_list = attack_surface.get('subdomains', [])
    api_endpoints_list = attack_surface.get('api_endpoints', [])
    hidden_routes_list = attack_surface.get('hidden_routes', [])
    js_discovered_list = attack_surface.get('js_discovered', [])
    target_url = scan_results.get('target', '')
    duration = scan_results.get('duration', 0)

    severity_data = json.dumps([
        scan_summary.get('critical_issues', 0),
        scan_summary.get('high_issues', 0),
        scan_summary.get('medium_issues', 0),
        scan_summary.get('low_issues', 0)
    ])
    vuln_types = json.dumps(list(issue_breakdown.keys()))
    vuln_counts = json.dumps(list(issue_breakdown.values()))
    findings_html = generate_findings_html(findings_list)
    total_chains = scan_summary.get('total_chains', 0)
    total_endpoints = scan_summary.get('total_endpoints_scanned', 0)

    chains = _collect_chains(findings_list)
    chains_html = _chain_html(chains)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugHunter AI - Security Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        :root {{
            --bg-dark: #0a0a0f;
            --bg-card: #12121a;
            --bg-card-hover: #1a1a25;
            --bg-section: #0e0e16;
            --text-primary: #e0e0e0;
            --text-secondary: #888;
            --text-muted: #555;
            --accent: #00ff88;
            --accent-dim: #00cc6a;
            --critical: #ff4444;
            --critical-bg: rgba(255, 68, 68, 0.1);
            --critical-border: #ff4444;
            --high: #ff8844;
            --high-bg: rgba(255, 136, 68, 0.1);
            --high-border: #ff8844;
            --medium: #ffbb33;
            --medium-bg: rgba(255, 187, 51, 0.1);
            --medium-border: #ffbb33;
            --low: #44cc44;
            --low-bg: rgba(68, 204, 68, 0.1);
            --low-border: #44cc44;
            --border: #2a2a3a;
        }}

        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
        }}

        .header {{
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
            padding: 30px 40px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}

        .logo {{
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        .logo-icon {{
            width: 50px;
            height: 50px;
            background: linear-gradient(135deg, var(--accent), #00aa55);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            font-weight: bold;
            color: #000;
        }}

        .logo h1 {{
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(90deg, var(--accent), #00ffaa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}

        .logo span {{
            color: var(--text-secondary);
            font-size: 14px;
        }}

        .stats-bar {{
            display: flex;
            gap: 20px;
        }}

        .stat-mini {{
            text-align: center;
            padding: 10px 20px;
            background: var(--bg-card);
            border-radius: 8px;
            border: 1px solid var(--border);
        }}

        .stat-mini-value {{
            font-size: 24px;
            font-weight: bold;
            color: var(--accent);
        }}

        .stat-mini-label {{
            font-size: 12px;
            color: var(--text-secondary);
        }}

        .container {{
            padding: 30px 40px;
            max-width: 1600px;
            margin: 0 auto;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }}

        .card {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 25px;
            border: 1px solid var(--border);
            transition: transform 0.2s, box-shadow 0.2s;
            position: relative;
            overflow: hidden;
        }}

        .card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
        }}

        .card.critical::before {{ background: var(--critical); }}
        .card.high::before {{ background: var(--high); }}
        .card.medium::before {{ background: var(--medium); }}
        .card.low::before {{ background: var(--low); }}

        .card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 40px rgba(0, 255, 136, 0.1);
        }}

        .card-label {{
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .card-value {{
            font-size: 42px;
            font-weight: bold;
        }}

        .card.critical .card-value {{ color: var(--critical); }}
        .card.high .card-value {{ color: var(--high); }}
        .card.medium .card-value {{ color: var(--medium); }}
        .card.low .card-value {{ color: var(--low); }}

        .row-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}

        .chart-card {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 25px;
            border: 1px solid var(--border);
        }}

        .chart-title {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .chart-title::before {{
            content: '';
            width: 4px;
            height: 20px;
            background: var(--accent);
            border-radius: 2px;
        }}

        .section-title {{
            font-size: 20px;
            font-weight: 700;
            margin: 30px 0 20px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .section-title::before {{
            content: '';
            width: 6px;
            height: 24px;
            background: linear-gradient(180deg, var(--accent), #00aa55);
            border-radius: 3px;
        }}

        .section-title .count {{
            font-size: 14px;
            color: var(--text-secondary);
            font-weight: 400;
        }}

        .findings-list {{
            max-height: 400px;
            overflow-y: auto;
        }}

        .finding-item {{
            background: var(--bg-card-hover);
            border-radius: 10px;
            padding: 15px;
            margin-bottom: 10px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-left: 3px solid var(--border);
            transition: background 0.15s;
        }}

        .finding-item:hover {{
            background: #1e1e2e;
        }}

        .finding-item.critical {{ border-left-color: var(--critical); }}
        .finding-item.high {{ border-left-color: var(--high); }}
        .finding-item.medium {{ border-left-color: var(--medium); }}
        .finding-item.low {{ border-left-color: var(--low); }}

        .finding-info h4 {{
            font-size: 14px;
            margin-bottom: 5px;
            font-family: 'Consolas', 'Monaco', monospace;
        }}

        .finding-info p {{
            font-size: 12px;
            color: var(--text-secondary);
        }}

        .severity-badge {{
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .severity-badge.critical {{ background: var(--critical); color: #fff; }}
        .severity-badge.high {{ background: var(--high); color: #000; }}
        .severity-badge.medium {{ background: var(--medium); color: #000; }}
        .severity-badge.low {{ background: var(--low); color: #000; }}

        .surface-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
        }}

        .surface-card {{
            background: var(--bg-card-hover);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
        }}

        .surface-card .number {{
            font-size: 32px;
            font-weight: bold;
            color: var(--accent);
        }}

        .surface-card .label {{
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 5px;
        }}

        .empty-state {{
            text-align: center;
            padding: 40px;
            color: var(--text-muted);
            font-style: italic;
        }}

        /* Chain Visualization */
        .chains-section {{
            margin-top: 30px;
        }}

        .chain-card {{
            background: var(--bg-card);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 16px;
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
        }}

        .chain-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
        }}

        .chain-card.critical::before {{ background: var(--critical); }}
        .chain-card.high::before {{ background: var(--high); }}
        .chain-card.medium::before {{ background: var(--medium); }}
        .chain-card.low::before {{ background: var(--low); }}

        .chain-card.critical {{ background: var(--critical-bg); border-color: var(--critical-border); }}
        .chain-card.high {{ background: var(--high-bg); border-color: var(--high-border); }}
        .chain-card.medium {{ background: var(--medium-bg); border-color: var(--medium-border); }}
        .chain-card.low {{ background: var(--low-bg); border-color: var(--low-border); }}

        .chain-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 10px;
        }}

        .chain-name {{
            font-size: 16px;
            font-weight: 600;
            margin-left: 10px;
        }}

        .chain-meta {{
            display: flex;
            gap: 16px;
            font-size: 13px;
            color: var(--text-secondary);
        }}

        .chain-score {{ color: var(--accent); font-weight: 600; }}
        .chain-prob {{ color: #88ccff; }}
        .chain-cvss {{ color: #ffcc44; }}

        .chain-path {{
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 14px;
            color: var(--accent);
            padding: 12px 16px;
            background: rgba(0, 255, 136, 0.05);
            border-radius: 8px;
            margin-bottom: 16px;
            line-height: 1.8;
        }}

        .chain-steps {{
            margin-bottom: 12px;
        }}

        .chain-step {{
            display: flex;
            align-items: baseline;
            gap: 12px;
            padding: 8px 0;
            border-bottom: 1px solid var(--border);
        }}

        .chain-step:last-child {{ border-bottom: none; }}

        .chain-step-num {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 28px;
            height: 28px;
            background: var(--accent);
            color: #000;
            border-radius: 50%;
            font-size: 12px;
            font-weight: 700;
            flex-shrink: 0;
        }}

        .chain-step-action {{
            font-weight: 600;
            font-size: 14px;
            min-width: 150px;
        }}

        .chain-step-desc {{
            font-size: 13px;
            color: var(--text-secondary);
        }}

        .chain-impact {{
            padding: 10px 16px;
            background: rgba(255, 136, 68, 0.08);
            border-radius: 8px;
            font-size: 13px;
            margin-bottom: 8px;
        }}

        .chain-impact strong {{
            color: var(--high);
        }}

        .chain-endpoint {{
            font-size: 12px;
            color: var(--text-muted);
            font-family: 'Consolas', 'Monaco', monospace;
        }}

        .chain-ep-label {{
            color: var(--text-secondary);
        }}

        .footer {{
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
            font-size: 13px;
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }}

        .footer a {{
            color: var(--accent);
            text-decoration: none;
        }}

        ::-webkit-scrollbar {{
            width: 6px;
        }}

        ::-webkit-scrollbar-track {{
            background: var(--bg-dark);
        }}

        ::-webkit-scrollbar-thumb {{
            background: var(--border);
            border-radius: 3px;
        }}

        ::-webkit-scrollbar-thumb:hover {{
            background: var(--accent-dim);
        }}

        @media (max-width: 1200px) {{
            .grid {{ grid-template-columns: repeat(2, 1fr); }}
            .row-grid {{ grid-template-columns: 1fr; }}
        }}

        @media (max-width: 768px) {{
            .header {{ padding: 20px; flex-direction: column; align-items: flex-start; }}
            .container {{ padding: 20px; }}
            .grid {{ grid-template-columns: 1fr; }}
            .stats-bar {{ flex-wrap: wrap; }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">
            <div class="logo-icon">BH</div>
            <div>
                <h1>BugHunter AI</h1>
                <span>Advanced Security Analysis Dashboard</span>
            </div>
        </div>
        <div class="stats-bar">
            <div class="stat-mini">
                <div class="stat-mini-value">{total_endpoints}</div>
                <div class="stat-mini-label">Endpoints</div>
            </div>
            <div class="stat-mini">
                <div class="stat-mini-value">{total_chains}</div>
                <div class="stat-mini-label">Chains</div>
            </div>
            <div class="stat-mini">
                <div class="stat-mini-value">{len(subdomains_list)}</div>
                <div class="stat-mini-label">Subdomains</div>
            </div>
            <div class="stat-mini">
                <div class="stat-mini-value">{duration:.0f}s</div>
                <div class="stat-mini-label">Duration</div>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="grid">
            <div class="card critical">
                <div class="card-label">Critical Issues</div>
                <div class="card-value">{scan_summary.get('critical_issues', 0)}</div>
            </div>
            <div class="card high">
                <div class="card-label">High Issues</div>
                <div class="card-value">{scan_summary.get('high_issues', 0)}</div>
            </div>
            <div class="card medium">
                <div class="card-label">Medium Issues</div>
                <div class="card-value">{scan_summary.get('medium_issues', 0)}</div>
            </div>
            <div class="card low">
                <div class="card-label">Low Issues</div>
                <div class="card-value">{scan_summary.get('low_issues', 0)}</div>
            </div>
        </div>

        <div class="row-grid">
            <div class="chart-card">
                <div class="chart-title">Severity Distribution</div>
                <canvas id="severityChart" height="200"></canvas>
            </div>
            <div class="chart-card">
                <div class="chart-title">Attack Surface</div>
                <div class="surface-grid">
                    <div class="surface-card">
                        <div class="number">{total_endpoints}</div>
                        <div class="label">Discovered Endpoints</div>
                    </div>
                    <div class="surface-card">
                        <div class="number">{len(subdomains_list)}</div>
                        <div class="label">Live Subdomains</div>
                    </div>
                    <div class="surface-card">
                        <div class="number">{len(api_endpoints_list)}</div>
                        <div class="label">API Endpoints</div>
                    </div>
                    <div class="surface-card">
                        <div class="number">{len(hidden_routes_list)}</div>
                        <div class="label">Hidden Routes</div>
                    </div>
                    <div class="surface-card">
                        <div class="number">{len(js_discovered_list)}</div>
                        <div class="label">JS Discovered</div>
                    </div>
                    <div class="surface-card">
                        <div class="number">{total_chains}</div>
                        <div class="label">Attack Chains</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="chart-card">
            <div class="chart-title">Vulnerability Breakdown</div>
            <canvas id="vulnChart" height="80"></canvas>
        </div>

        <div class="chart-card" style="margin-top: 20px;">
            <div class="chart-title">Top Findings ({len(findings_list)} total)</div>
            <div class="findings-list">
                {findings_html}
            </div>
        </div>

        <div class="chains-section">
            <div class="section-title">
                Attack Chains <span class="count">({len(chains)} detected)</span>
            </div>
            {chains_html}
        </div>
    </div>

    <div class="footer">
        Generated by <a href="#">BugHunter AI v2.0</a> | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: {target_url}
    </div>

    <script>
        const severityData = {{
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{{
                data: {severity_data},
                backgroundColor: ['#ff4444', '#ff8844', '#ffbb33', '#44cc44'],
                borderWidth: 0
            }}]
        }};

        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: severityData,
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom', labels: {{ color: '#888' }} }}
                }}
            }}
        }});

        const vulnTypes = {vuln_types};
        const vulnCounts = {vuln_counts};

        new Chart(document.getElementById('vulnChart'), {{
            type: 'bar',
            data: {{
                labels: vulnTypes,
                datasets: [{{
                    label: 'Findings',
                    data: vulnCounts,
                    backgroundColor: '#00ff88',
                    borderRadius: 6
                }}]
            }},
            options: {{
                responsive: true,
                scales: {{
                    x: {{ grid: {{ display: false }}, ticks: {{ color: '#888' }} }},
                    y: {{ grid: {{ color: '#2a2a3a' }}, ticks: {{ color: '#888' }} }}
                }},
                plugins: {{
                    legend: {{ display: false }}
                }}
            }}
        }});
    </script>
</body>
</html>"""

    return html


def generate_findings_html(findings):
    html = ""

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    sorted_findings = sorted(
        findings,
        key=lambda x: (severity_order.get(x.get("scan_results", {}).get("severity", "low"), 99),
                      x.get("scan_results", {}).get("score", 0)),
        reverse=True
    )

    for i, finding in enumerate(sorted_findings[:20]):
        endpoint = finding.get("endpoint", "Unknown")
        method = finding.get("method", "GET")
        severity = finding.get("scan_results", {}).get("severity", "low")
        score = finding.get("scan_results", {}).get("score", 0)
        issues = finding.get("scan_results", {}).get("issues", [])

        issue_types = ", ".join([i.get("type", "unknown") for i in issues[:2]]) or "Analyzed"

        html += f"""
        <div class="finding-item {severity}">
            <div class="finding-info">
                <h4>{method} {endpoint[:60]}{'...' if len(endpoint) > 60 else ''}</h4>
                <p>{issue_types} | Score: {score}</p>
            </div>
            <span class="severity-badge {severity}">{severity}</span>
        </div>
        """

    return html


def generate_dashboard(scan_results, attack_surface, summary, output_path="output/dashboard.html"):
    html = generate_standalone_dashboard(scan_results, attack_surface, summary)

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
