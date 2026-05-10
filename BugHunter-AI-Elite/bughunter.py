import json
import asyncio
import argparse
import time
import logging
from datetime import datetime
from pathlib import Path
import httpx
import sys
import os
sys.path.insert(0, str(Path(__file__).parent))

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
if sys.platform == "win32":
    import codecs
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")

from modules.input_module import validate_target, normalize_url
from modules.crawler import run_crawler
from modules.js_intelligence import run_js_analysis
from modules.behavior_profiling import run_behavior_profiling
from modules.logic_engine import run_logic_engine
from modules.heuristic_engine import run_heuristic_engine
from modules.scoring_engine import calculate_score
from modules.vuln_chaining import chain_vulnerabilities
from modules.chain_engine import build_attack_chains
from modules.ai_engine import run_ai_analysis
from modules.mutation_engine import run_mutation_tests, MutationEngine
from modules.auth_simulation import MultiUserAuthSimulator
from modules.attack_surface import expand_attack_surface
from modules.scheduler import create_scheduler, create_executor, run_scheduled_tasks
from modules.ai_planner import create_strategic_plan, prioritize_targets
from modules.learning_system import create_learning_system, record_success
from modules.script_generator import generate_scripts
from modules.report_generator import generate_report, ReportGenerator
from modules.dashboard import generate_dashboard
from modules.logging_config import logger
from modules.rag_loader import RAGLoader
from modules.rag_integration import RAGIntegration
from modules.vuln_validator import VulnerabilityValidator
from modules.attack_flow_engine import AttackFlowEngine, ESCALATION_CHAINS
from modules.adaptive_learning import AdaptiveLearningController
from modules.performance_optimizer import PerformanceOptimizer
from modules.console_output import (
    console, error_console, make_progress, print_banner,
    print_phase, print_step, print_finding, print_summary_table, print_completion,
)


class BugHunterAI:
    def __init__(self, config_path="config.json"):
        with open(config_path, "r") as f:
            self.config = json.load(f)
            
        with open("knowledge_base.json", "r") as f:
            self.knowledge_base = json.load(f)
        
        self.results = []
        self.config["output_dir"] = "output"
        self.config["script_dir"] = "scripts"
        self.all_js_endpoints = []
        
        self.scheduler = create_scheduler(max_concurrent=self.config.get("max_workers", 10))
        self.executor = create_executor(max_workers=15, rate_limit=self.config.get("rate_limit", 30))
        self.learning = create_learning_system()
        
        self.rag_loader = RAGLoader("rag")
        self.rag_loader.load_all()
        self.rag = RAGIntegration(self.config, self.rag_loader)
        logger.info(f"RAG loaded: {len(self.rag_loader.vuln_types)} vulnerability types, {len(self.rag_loader.modules)} modules")
        
        self.flow_engine = AttackFlowEngine(
            config=self.config,
            rag_loader=self.rag_loader,
            validator=None,
            learning_system=self.learning,
            adaptive_learning=AdaptiveLearningController(self.learning, self.rag_loader),
            perf_optimizer=PerformanceOptimizer(self.config),
        )

        self._validator = None

        self.auth_cache = None
        
        self.scan_start_time = None
        self.scan_data = {
            "endpoints": [],
            "attack_surface": {},
            "findings": []
        }
    
    def _extract_params_from_url(self, url):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        qs_params = list(parse_qs(parsed.query).keys())
        
        if not qs_params:
            api_params = []
            path_lower = parsed.path.lower()
            if "/user" in path_lower or "/profile" in path_lower or "/account" in path_lower:
                api_params.extend(["id", "user_id"])
            if "/post" in path_lower or "/comment" in path_lower or "/article" in path_lower:
                api_params.extend(["id", "post_id"])
            if "/search" in path_lower or "/query" in path_lower or "/filter" in path_lower:
                api_params.extend(["q", "query", "search", "filter"])
            if "/login" in path_lower or "/auth" in path_lower or "/session" in path_lower:
                api_params.extend(["username", "password", "token"])
            if "/admin" in path_lower or "/config" in path_lower or "/settings" in path_lower:
                api_params.extend(["id", "config", "key"])
            if "/upload" in path_lower or "/file" in path_lower:
                api_params.extend(["file", "path", "url"])
            if api_params:
                return api_params
            
            if "/api" in path_lower or "/rest" in path_lower or "/graphql" in path_lower:
                return ["id", "query", "page"]
        
        return qs_params
    
    async def run(self, target_url, quiet=False):
        self.scan_start_time = time.time()
        self.quiet = quiet

        if not quiet:
            print_banner()
            console.print(f"\n[dim]Target:[/dim] [bold]{target_url}[/bold]\n")

        valid, msg = validate_target(target_url)
        if not valid:
            error_console.print(f"[red]Invalid target:[/red] {msg}")
            return None

        normalized_url = normalize_url(target_url)

        if not quiet:
            print_phase(1, "Strategic AI Planning")
        attack_plan = await create_strategic_plan(
            self.config,
            [{"url": normalized_url, "priority_score": 10}],
            {"domain": normalized_url}
        )
        if not quiet:
            print_step("[+]", f"Created {len(attack_plan.get('attack_phases', []))} attack phases", "green")

        if not quiet:
            print_phase(2, "Attack Surface Expansion")
        surface_data = await expand_attack_surface(self.config, normalized_url)

        if not quiet:
            for subdomain in surface_data.get("subdomains", [])[:5]:
                print_step("+", f"Live subdomain: {subdomain.get('subdomain')}", "cyan")

        self.scan_data["attack_surface"] = surface_data

        if not quiet:
            print_phase(3, "Crawler & Recon")

        with make_progress() as progress:
            task = progress.add_task("Crawling endpoints...", total=100)
            endpoints = await run_crawler(self.config, normalized_url)
            progress.update(task, completed=100)

        surface_endpoints = []
        seen_urls = set(e["url"] for e in endpoints)

        for ep in surface_data.get("api_endpoints", []):
            url = ep.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                params = self._extract_params_from_url(url)
                surface_endpoints.append({
                    "url": url,
                    "method": ep.get("method", "GET"),
                    "params": params,
                    "status_code": ep.get("status", 0),
                    "source": "attack_surface_api",
                    "depth": 0
                })

        for ep in surface_data.get("hidden_routes", []):
            url = ep.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                params = self._extract_params_from_url(url)
                surface_endpoints.append({
                    "url": url,
                    "method": ep.get("method", "GET"),
                    "params": params,
                    "status_code": ep.get("status", 0),
                    "source": "attack_surface_hidden",
                    "depth": 0
                })

        for ep in surface_data.get("sensitive_params", []):
            url = ep.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                params = ep.get("params", self._extract_params_from_url(url))
                surface_endpoints.append({
                    "url": url,
                    "method": ep.get("method", "GET"),
                    "params": params,
                    "status_code": ep.get("status", 0),
                    "source": "attack_surface_params",
                    "depth": 0
                })

        endpoints.extend(surface_endpoints)
        if not quiet:
            print_step("+", f"Added {len(surface_endpoints)} endpoints from attack surface", "cyan")

        js_discovered_endpoints = []

        if not quiet:
            print_phase(4, "JS Intelligence + Integration")

        for ep in endpoints[:15]:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.get(ep["url"])
                    if resp.status_code == 200:
                        js_info = await run_js_analysis(self.config, resp.text, ep["url"])
                        ep["js_endpoints"] = js_info.get("endpoints", [])
                        ep["js_tokens"] = js_info.get("tokens_found", [])
                        ep["js_hidden_routes"] = js_info.get("hidden_routes", [])

                        for js_ep in js_info.get("endpoints", []):
                            if js_ep.startswith("/"):
                                full_ep = normalized_url.rstrip("/") + js_ep
                                if full_ep not in [e["url"] for e in endpoints]:
                                    js_discovered_endpoints.append({
                                        "url": full_ep,
                                        "method": "GET",
                                        "params": [],
                                        "source": "js_discovery",
                                        "depth": ep.get("depth", 0) + 1
                                    })
                        self.all_js_endpoints.extend(js_info.get("endpoints", []))

                        self.learning.record_endpoint_pattern(ep["url"], ep.get("method", "GET"), ep.get("params", []))
            except Exception as e:
                logger.debug(f"JS analysis error: {e}")

        endpoints.extend(js_discovered_endpoints)
        if not quiet:
            print_step("+", f"Added {len(js_discovered_endpoints)} endpoints from JS", "cyan")

        self.scan_data["endpoints"] = endpoints

        if not endpoints:
            console.print("[yellow]No endpoints found[/yellow]")
            return None

        if not quiet:
            print_phase(5, f"AI Prioritization ({len(endpoints)} endpoints)")
        prioritized = await prioritize_targets(self.config, endpoints, self.knowledge_base)
        prioritized_endpoints = prioritized.get("prioritized", endpoints)

        if not quiet:
            print_phase(6, "Processing endpoints")

        total_eps = len([e for e in prioritized_endpoints if e.get("params")])
        with make_progress() as progress:
            scan_task = progress.add_task("Scanning endpoints...", total=total_eps)

            for i, endpoint in enumerate(prioritized_endpoints):
                if not endpoint.get("params"):
                    continue

                progress.update(scan_task, advance=1, description=f"[{i+1}/{total_eps}] {endpoint['url'][:50]}...")

                try:
                    profile = await run_behavior_profiling(self.config, endpoint)
                    if not profile:
                        continue

                    rag_findings = self.rag.detect_vulnerabilities(endpoint)

                    adaptive_order = self.flow_engine.get_adaptive_vuln_order(endpoint["url"])

                    logic_findings = await run_logic_engine(
                        self.config, self.knowledge_base, endpoint, profile
                    )

                    logic_findings.extend(rag_findings)

                    fast_mode = self.config.get("fast_mode", False)

                    heuristic_findings = []
                    if not fast_mode:
                        heuristic_findings = await run_heuristic_engine(self.config, endpoint)

                    mutation_results = []
                    if not fast_mode:
                        mutation_results = await run_mutation_tests(self.config, endpoint)

                    for mut in mutation_results:
                        if not any(f.get("type") == mut.get("type") and f.get("param") == mut.get("param") for f in logic_findings):
                            logic_findings.append({
                                "type": mut.get("type"),
                                "param": mut.get("param"),
                                "reason": mut.get("evidence", "mutation test"),
                                "confidence": mut.get("confidence", "medium")
                            })

                            if mut.get("confidence") == "high":
                                record_success(mut.get("type"), endpoint["url"], mut.get("payload", ""), mut.get("param", ""))

                    if self.config.get("deep_scan", False):
                        flow_findings = await self._run_attack_flow(endpoint, profile, logic_findings)
                        logic_findings.extend(flow_findings)

                    if not fast_mode:
                        logic_findings = await self._validate_findings(endpoint, logic_findings, profile)

                    heuristic_findings = []
                    if not fast_mode:
                        heuristic_findings = await self._validate_heuristics(endpoint, heuristic_findings, profile)

                    score_results = calculate_score(endpoint, logic_findings, heuristic_findings, fast_mode=fast_mode)

                    if not quiet:
                        print_step(">>", f"Score: {score_results['score']} ({score_results['severity']})", "white")

                    if score_results["score"] < 2 and not logic_findings:
                        continue

                    chain_results = chain_vulnerabilities(
                        self.knowledge_base, logic_findings, heuristic_findings, score_results
                    )
                    if chain_results is None:
                        chain_results = {"chains": []}

                    all_findings_for_chains = logic_findings + heuristic_findings
                    chain_mode = self.config.get("chain_mode", "detailed")
                    attack_chain_results = build_attack_chains(all_findings_for_chains, endpoint["url"], mode=chain_mode)
                    if attack_chain_results.get("chains"):
                        chain_results["attack_chains"] = attack_chain_results["chains"]
                        chain_results["total_attack_chains"] = attack_chain_results["total_chains"]
                        chain_results["max_chain_severity"] = attack_chain_results["max_severity"]
                        chain_results["max_chain_score"] = attack_chain_results["max_score"]

                    ai_results = await run_ai_analysis(
                        self.config, endpoint, logic_findings, heuristic_findings,
                        score_results, chain_results, self.rag
                    )
                    if ai_results is None:
                        ai_results = {"ai_analysis": None, "ai_error": "No response"}

                    ai_suggested_tests = []
                    if ai_results.get("ai_analysis"):
                        ai_suggested_tests = await self._execute_ai_feedback_loop(
                            endpoint, logic_findings, ai_results
                        )

                        for test_result in ai_suggested_tests:
                            if test_result.get("confirmed"):
                                logic_findings.append({
                                    "type": test_result.get("type"),
                                    "param": test_result.get("param"),
                                    "reason": test_result.get("reason", "AI confirmed"),
                                    "confidence": "high"
                                })
                                self.learning.record_true_positive(test_result.get("type"), endpoint["url"])

                    auth_results = await self._run_auth_tests(endpoint)
                    if auth_results:
                        logic_findings.extend(auth_results)

                    scripts = generate_scripts(self.config, endpoint, logic_findings, score_results)

                    if logic_findings:
                        for finding in logic_findings:
                            self.learning.record_vulnerability(
                                finding.get("type"),
                                endpoint["url"],
                                score_results.get("severity", "low"),
                                confirmed=finding.get("confidence") == "high"
                            )

                    for finding in logic_findings:
                        if not quiet:
                            print_finding(
                                finding.get("type", "unknown"),
                                finding.get("param", "?"),
                                score_results.get("severity", "low"),
                                finding.get("confidence", "low"),
                                endpoint["url"],
                            )

                    report = generate_report(
                        self.config, self.knowledge_base, endpoint,
                        logic_findings, heuristic_findings, score_results,
                        chain_results, ai_results, scripts
                    )

                    self.results.append(report)

                except Exception as e:
                    logger.error(f"Error scanning {endpoint.get('url', 'unknown')}: {e}")
                    continue

        scan_duration = time.time() - self.scan_start_time

        self.learning.record_scan_session(target_url, len(self.results), scan_duration)

        if not quiet:
            print_phase(7, "Generating reports")
        report_gen = ReportGenerator(self.config, self.knowledge_base)
        summary = report_gen.generate_summary_report(self.results)

        report_gen.save_report({
            "summary": summary,
            "findings": self.results,
            "attack_surface": {
                "subdomains": surface_data.get("subdomains", []),
                "api_endpoints": surface_data.get("api_endpoints", []),
                "hidden_routes": surface_data.get("hidden_routes", []),
                "js_discovered": self.all_js_endpoints
            },
            "ai_plan": attack_plan,
            "scan_metadata": {
                "duration": scan_duration,
                "timestamp": datetime.now().isoformat()
            }
        })

        if not quiet:
            print_phase(8, "Generating visual dashboard")
        generate_dashboard(
            {"findings": self.results, "target": target_url, "duration": scan_duration},
            surface_data,
            summary,
            "output/dashboard.html"
        )

        self.scan_data["findings"] = self.results

        return {
            "summary": summary,
            "results": self.results,
            "attack_surface": surface_data,
            "ai_plan": attack_plan,
            "duration": scan_duration
        }
    
    async def _execute_ai_feedback_loop(self, endpoint, initial_findings, ai_results):
        executed_tests = []
        
        prompt_analysis = ai_results.get("ai_analysis", "")
        
        vuln_patterns = {
            "xss": ["'<script", "onerror", "onload", "javascript:"],
            "sql": ["' OR '1'='1", "UNION", "SLEEP", "--"],
            "idor": ["id=", "user_id=", "increment"],
            "ssrf": ["localhost", "169.254", "metadata"]
        }
        
        for vuln_type, indicators in vuln_patterns.items():
            if any(ind.lower() in prompt_analysis.lower() for ind in indicators):
                logger.info(f"      → Executing AI-suggested {vuln_type} tests...")
                
                mutation = MutationEngine(self.config)
                test_results = await mutation.mutate_and_test(endpoint, vuln_type)
                
                for result in test_results:
                    executed_tests.append({
                        "type": result.get("type"),
                        "param": result.get("param"),
                        "payload": result.get("payload"),
                        "confirmed": result.get("confidence") == "high",
                        "reason": f"AI suggested test - {result.get('evidence', 'confirmed')}"
                    })
                
                await mutation.close()
        
        return executed_tests
    
    async def _run_auth_tests(self, endpoint):
        results = []

        params = endpoint.get("params", [])
        id_params = ["id", "user_id", "uid", "account", "profile"]
        has_id_param = any(any(ip in p.lower() for ip in id_params) for p in params)
        if not has_id_param:
            return results

        if self.auth_cache and self.auth_cache.get("sessions") and len(self.auth_cache["sessions"]) >= 2:
            simulator = self.auth_cache["simulator"]
        else:
            try:
                simulator = MultiUserAuthSimulator(self.config)
                base_url = endpoint["url"].split("?")[0]
                url_parts = base_url.rsplit("/", 1)
                app_base = url_parts[0] if len(url_parts) > 1 else base_url

                logged_in = await simulator.try_default_credentials(app_base)
                if len(logged_in) < 2:
                    await simulator.cleanup()
                    self.auth_cache = {"sessions": [], "simulator": None}
                    return results

                self.auth_cache = {
                    "sessions": logged_in,
                    "simulator": simulator,
                    "base_url": app_base,
                }
            except Exception as e:
                logger.debug(f"Auth setup error: {e}")
                return results

        try:
            user_a = self.auth_cache["sessions"][0]
            user_b = self.auth_cache["sessions"][1]

            id_param = next((p for p in params if any(ip in p.lower() for ip in id_params)), params[0])
            target_id = user_b.get("user_id", "2")

            test_url = endpoint["url"].split("?")[0]
            idor_results = await simulator.test_idor(test_url, user_a, [target_id])
            for r in idor_results:
                results.append({
                    "type": "idor",
                    "param": r.get("victim_id", id_param),
                    "reason": r.get("reason", "IDOR confirmed via auth simulation"),
                    "confidence": r.get("confidence", "high"),
                    "validation_status": "confirmed" if r.get("access_granted") else "likely",
                    "auth_sim": True,
                })

            admin_ep = f"{self.auth_cache['base_url']}/api/admin/users"
            priv_results = await simulator.test_privilege_escalation(admin_ep, user_a, [{"name": "list_admin_users", "method": "GET"}])
            for r in priv_results:
                if r.get("success"):
                    results.append({
                        "type": "idor",
                        "param": "role",
                        "reason": f"Privilege escalation: {r['user_role']} accessed admin endpoint",
                        "confidence": "high",
                        "validation_status": "confirmed",
                        "auth_sim": True,
                    })
        except Exception as e:
            logger.debug(f"Auth test error: {e}")

        return results
    
    async def _run_attack_flow(self, endpoint, profile, existing_findings):
        flow_findings = []
        
        vuln_types_to_test = set()
        for finding in existing_findings:
            vtype = finding.get("type", "")
            if vtype:
                vuln_types_to_test.add(vtype)
        
        params = endpoint.get("params", [])
        if not params:
            return flow_findings
        
        baseline = profile.get("baseline", {})
        
        self.flow_engine.validator = VulnerabilityValidator(self.config, self.rag_loader)
        
        for vuln_type in vuln_types_to_test:
            for param in params:
                try:
                    flow_result = await self.flow_engine.execute_flow(
                        vuln_type=vuln_type,
                        endpoint=endpoint["url"],
                        param=param,
                        baseline_response=baseline,
                    )
                    
                    if flow_result.get("result") in ("confirmed", "likely"):
                        for finding in flow_result.get("findings", []):
                            flow_findings.append({
                                "type": finding.get("type", vuln_type),
                                "param": finding.get("param", param),
                                "reason": finding.get("reason", f"Flow confirmed: {finding.get('stage', '')}"),
                                "confidence": finding.get("confidence", "high"),
                                "validation_status": "confirmed" if flow_result["result"] == "confirmed" else "likely",
                                "flow_stage": finding.get("stage", ""),
                                "flow_technique": finding.get("technique", ""),
                                "flow_payload": finding.get("payload", ""),
                                "escalation_stages": flow_result.get("escalation_stages_completed", 0),
                            })
                            
                            if finding.get("confidence") == "high":
                                self.learning.record_true_positive(vuln_type, endpoint["url"])
                    
                    elif flow_result.get("result") == "suspected" and flow_result.get("findings"):
                        for finding in flow_result.get("findings", []):
                            flow_findings.append({
                                "type": finding.get("type", vuln_type),
                                "param": finding.get("param", param),
                                "reason": finding.get("reason", "Flow suspected"),
                                "confidence": "low",
                                "validation_status": "suspected",
                                "flow_stage": finding.get("stage", ""),
                                "flow_technique": finding.get("technique", ""),
                            })
                
                except Exception as e:
                    logger.debug(f"Flow engine error for {vuln_type}/{param}: {e}")
                    continue
        
        try:
            await self.flow_engine.validator.close()
        except Exception:
            pass
        
        if flow_findings:
            logger.info(f"    - Flow engine: {len(flow_findings)} findings from adaptive flows")
        
        return flow_findings
    
    async def _get_validator(self):
        if self._validator is None:
            self._validator = VulnerabilityValidator(self.config, self.rag_loader)
        return self._validator

    async def _validate_findings(self, endpoint, findings, profile):
        if not findings:
            return findings
        
        validator = await self._get_validator()
        baseline = profile.get("baseline", {})
        
        confirmed_findings = []
        rejected_count = 0
        
        for finding in findings:
            vuln_type = finding.get("type", "")
            param = finding.get("param", "")
            confidence = finding.get("confidence", "low")
            
            if vuln_type == "ssrf" and confidence == "low":
                finding["confidence"] = "low"
                finding["validation_status"] = "skipped (param-based only)"
                rejected_count += 1
                if not getattr(self, "quiet", False):
                    print_finding(vuln_type, param, "low", "rejected", endpoint["url"])
                continue
            
            if vuln_type == "open_redirect" and confidence == "low":
                finding["confidence"] = "low"
                finding["validation_status"] = "skipped (param-based only)"
                rejected_count += 1
                if not getattr(self, "quiet", False):
                    print_finding(vuln_type, param, "low", "rejected", endpoint["url"])
                continue
            
            test_payloads = self._get_validation_payloads(vuln_type)
            if not test_payloads:
                finding["validation_status"] = "skipped (no test payloads)"
                rejected_count += 1
                continue
            
            validation_confirmed = False
            validation_likely = False
            for payload in test_payloads:
                result = await validator.validate_with_payload(
                    endpoint, vuln_type, baseline, payload, param
                )
                
                tier = result.get("reason", "").split(":")[0].lower() if result.get("reason") else ""
                if "confirmed" in tier or result.get("confirmed"):
                    validation_confirmed = True
                    finding["confidence"] = result.get("confidence", "high")
                    finding["validation_status"] = "confirmed"
                    finding["validation_reason"] = result.get("reason", "")
                    finding["matched_patterns"] = result.get("matched_patterns", [])
                    if not getattr(self, "quiet", False):
                        print_finding(vuln_type, param, finding.get("confidence", "high"), "confirmed", endpoint["url"])
                    break
                elif "likely" in tier and not validation_likely:
                    validation_likely = True
                    finding["confidence"] = result.get("confidence", "medium")
                    finding["validation_status"] = "likely"
                    finding["validation_reason"] = result.get("reason", "")
                    finding["matched_patterns"] = result.get("matched_patterns", [])
                    if not getattr(self, "quiet", False):
                        print_finding(vuln_type, param, finding.get("confidence", "medium"), "likely", endpoint["url"])
                elif result.get("suspected"):
                    finding["confidence"] = "low"
                    finding["validation_status"] = "suspected"
                    finding["validation_reason"] = result.get("reason", "")
                    if not getattr(self, "quiet", False):
                        print_finding(vuln_type, param, "low", "suspected", endpoint["url"])
            
            if validation_confirmed:
                confirmed_findings.append(finding)
            elif validation_likely:
                confirmed_findings.append(finding)
            elif finding.get("validation_status") == "suspected":
                rejected_count += 1
            else:
                rejected_count += 1
        
        if rejected_count > 0 and not getattr(self, "quiet", False):
            print_step("-", f"Validation: {len(confirmed_findings)} confirmed, {rejected_count} rejected", "dim")
        
        await validator.close()
        
        return confirmed_findings
    
    async def _validate_heuristics(self, endpoint, heuristics, profile):
        if not heuristics:
            return heuristics
        
        validator = await self._get_validator()
        baseline = profile.get("baseline", {})
        
        confirmed_heuristics = []
        
        for h in heuristics:
            h_type = h.get("type", "")
            
            if h_type in ["status_change", "response_diff", "content_diff"]:
                test_params = {endpoint.get("params", ["test"])[0]: "validation_test"}
                method = endpoint.get("method", "GET")
                
                try:
                    async with httpx.AsyncClient(
                        timeout=10,
                        headers={"User-Agent": self.config.get("user_agent", "BugHunter-AI/v2.0")},
                        follow_redirects=False
                    ) as client:
                        if method == "GET":
                            resp = await client.get(endpoint["url"], params=test_params)
                        else:
                            resp = await client.post(endpoint["url"], data=test_params)
                        
                        payload_response = {
                            "status_code": resp.status_code,
                            "text": resp.text,
                            "length": len(resp.content)
                        }
                        
                        validation = validator.validate_response(
                            baseline, payload_response, "general"
                        )
                        
                        if validation.get("confirmed") or validation.get("suspected"):
                            confirmed_heuristics.append(h)
                        else:
                            logger.debug(f"      [-] Rejected heuristic {h_type}: no response change")
                
                except Exception as e:
                    logger.debug(f"      [-] Heuristic validation error: {e}")
                    confirmed_heuristics.append(h)
            
            else:
                confirmed_heuristics.append(h)
        
        await validator.close()
        return confirmed_heuristics
    
    def _get_validation_payloads(self, vuln_type):
        from modules.payload_loader import get_payload_loader
        loader = get_payload_loader()
        
        module_map = {
            "xss": "xss",
            "sql_injection": "sql-injection",
            "sqli": "sql-injection",
            "command_injection": "command-injection",
            "ssti": "ssti",
            "path_traversal": "path-traversal",
            "ssrf": "ssrf-payloads",
            "xxe": "xxe",
            "idor": "idor",
            "deserialization": "deserialization",
            "jwt": "jwt",
            "graphql": "graphql",
            "csrf": "csrf",
            "race_conditions": "race-conditions"
        }
        
        module = module_map.get(vuln_type, vuln_type)
        
        payloads_by_type = {}
        
        try:
            entries = loader.load_payloads(module, level="basic", safe_only=True, limit=20)
            payloads_by_type[vuln_type] = [e.payload for e in entries]
        except Exception:
            payloads_by_type[vuln_type] = []
        
        if not payloads_by_type.get(vuln_type):
            payloads_by_type[vuln_type] = []
        
        return payloads_by_type.get(vuln_type, [])


async def main():
    parser = argparse.ArgumentParser(
        description="BugHunter AI - Elite Cybersecurity Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bughunter.py https://target.com
  python bughunter.py https://target.com --deep --chain-mode summary
  python bughunter.py https://target.com --quiet
  python bughunter.py https://target.com --verbose --chain-mode detailed
        """,
    )
    parser.add_argument("target", help="Target URL to scan")
    parser.add_argument("--config", default="config.json", help="Config file path")
    parser.add_argument("--deep", action="store_true", help="Enable deep scanning with AI feedback")
    parser.add_argument("--chain-mode", choices=["summary", "detailed"], default="detailed",
                        help="Chain output mode: summary (compact) or detailed (step-by-step + confidence)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output, only results")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show debug-level logs")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    scanner = BugHunterAI(args.config)
    if args.chain_mode != "detailed":
        scanner.config["chain_mode"] = args.chain_mode

    results = await scanner.run(args.target, quiet=args.quiet)
    
    if results:
        summary = results["summary"]["scan_summary"]
        duration = results.get("duration", 0)
        attack_surface = results.get("attack_surface", {})
        ai_plan = results.get("ai_plan", {})

        print_summary_table(summary, duration, attack_surface, ai_plan)
        print_completion()
    else:
        console.print("[yellow]Scan failed or no results[/yellow]")


if __name__ == "__main__":
    asyncio.run(main())