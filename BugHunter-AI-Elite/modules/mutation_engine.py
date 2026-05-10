import json
import re
import time
from urllib.parse import quote, urlencode
from modules.logging_config import logger
from modules.vuln_validator import VulnerabilityValidator
from modules.execution_controller import get_execution_controller, ExecutionController


class MutationEngine:
    def __init__(self, config):
        self.config = config
        self.payloads = self._load_payloads()
        self.user_agent = config.get("user_agent", "BugHunter-AI/v1.0")
        self.timeout = config.get("request_timeout", 10)
        self._exec_controller = None
        self._session = None
        self._use_controller = True
    
    @property
    def exec_controller(self):
        if self._exec_controller is None and self._use_controller:
            try:
                self._exec_controller = get_execution_controller(self.config)
            except Exception:
                self._use_controller = False
        return self._exec_controller
    
    def _load_payloads(self):
        try:
            with open("payloads.json", "r") as f:
                return json.load(f)
        except:
            return {}
    
    def _encode_payload(self, payload, encoding):
        if encoding == "url":
            return quote(payload)
        elif encoding == "double_url":
            return quote(quote(payload))
        elif encoding == "html":
            return payload.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        elif encoding == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif encoding == "mixed":
            return quote(payload)[:2] + payload[2:] + quote(payload)[-2:]
        return payload
    
    def get_payloads_for_type(self, vuln_type):
        return self.payloads.get(vuln_type, [])
    
    def generate_id_mutation(self, param_type):
        payloads = []
        
        id_patterns = self.payloads.get("fuzzing", {}).get("id_enumeration", {})
        
        for pattern in id_patterns.get("patterns", []):
            if "start" in pattern and "end" in pattern:
                for i in range(pattern["start"], pattern["end"], pattern.get("step", 1)):
                    payloads.append(str(i))
            elif "values" in pattern:
                payloads.extend(pattern["values"])
        
        context = id_patterns.get("context_aware", [])
        for ctx in context:
            if ctx["param_type"] in param_type.lower():
                base_payloads = payloads.copy()
                new_payloads = []
                for p in base_payloads:
                    for prefix in ctx.get("prefixes", [""]):
                        for suffix in ctx.get("suffixes", [""]):
                            new_payloads.append(f"{prefix}{p}{suffix}")
                payloads.extend(new_payloads)
                break
        
        return payloads[:100]
    
    def generate_xss_payloads(self, filter_context=None):
        payloads = []
        
        basic_xss = self.payloads.get("xss", {}).get("basic", [])
        bypass_xss = self.payloads.get("xss", {}).get("filter_bypass", [])
        encoding = self.payloads.get("xss", {}).get("encoding_variations", {})
        
        all_payloads = basic_xss + bypass_xss
        payloads.extend(all_payloads)
        
        if encoding.get("html_entities"):
            encoded = [self._encode_payload(p, "html") for p in all_payloads]
            payloads.extend(encoded)
            
        if encoding.get("double_url_encode"):
            encoded = [self._encode_payload(p, "double_url") for p in all_payloads]
            payloads.extend(encoded)
            
        if encoding.get("unicode_escape"):
            encoded = [self._encode_payload(p, "unicode") for p in all_payloads[:10]]
            payloads.extend(encoded)
        
        return payloads[:50]
    
    def generate_sql_payloads(self, injection_type="error_based"):
        return self.payloads.get("sql_injection", {}).get(injection_type, [])[:30]
    
    def generate_ssrf_payloads(self):
        payloads = []
        
        payloads.extend(self.payloads.get("ssrf", {}).get("internal_aws", []))
        payloads.extend(self.payloads.get("ssrf", {}).get("internal_network", []))
        payloads.extend(self.payloads.get("ssrf", {}).get("bypass_techniques", []))
        
        return payloads[:30]
    
    def generate_path_traversal_payloads(self):
        return self.payloads.get("path_traversal", {}).get("basic", [])[:30]
    
    def generate_open_redirect_payloads(self):
        return self.payloads.get("open_redirect", {}).get("payloads", [])[:20]
    
    def generate_command_injection_payloads(self, os_type="unix"):
        return self.payloads.get("command_injection", {}).get(os_type, [])[:20]
    
    async def init_session(self):
        if self._session:
            await self._session.aclose()
        self._session = None
    
    async def close(self):
        if self._exec_controller:
            await self._exec_controller.close()
            self._exec_controller = None
        if self._session:
            await self._session.aclose()
            self._session = None
    
    async def mutate_and_test(self, endpoint, vuln_type, mutations=None):
        await self.init_session()
        validator = VulnerabilityValidator(self.config, None)
        
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        params = endpoint.get("params", [])
        
        if not params:
            await self.close()
            return []
        
        baseline = await self._send_request(url, method, {})
        
        results = []
        
        vuln_type_map = {
            "id_enumeration": "idor",
            "sql_error": "sql_injection",
            "sql_blind": "sql_injection",
        }
        vuln_type = vuln_type_map.get(vuln_type, vuln_type)

        if vuln_type == "xss":
            payloads = mutations or self.generate_xss_payloads()
            test_param = params[0]
            
            for payload in payloads:
                test_params = {test_param: payload}
                response = await self._send_request(url, method, test_params)
                
                if response:
                    validated = validator.validate_response(baseline, response, "xss", payload)
                    if validated.get("confirmed"):
                        reflected = payload in response.get("text", "")
                        if reflected or self._detect_xss(response, payload):
                            results.append({
                                "param": test_param,
                                "payload": payload,
                                "type": "xss",
                                "confidence": "high",
                                "evidence": "payload reflected in response",
                                "validated": True
                            })
                    else:
                        logger.debug(f"  [Mutation] Rejected XSS payload: no response change")
        
        elif vuln_type == "sql_injection":
            payloads = mutations or self.generate_sql_payloads()
            
            for param in params:
                for payload in payloads:
                    test_params = {param: payload}
                    response = await self._send_request(url, method, test_params)
                    
                    if response:
                        validated = validator.validate_response(baseline, response, "sqli", payload)
                        if validated.get("confirmed") or self._detect_sql_error(response):
                            results.append({
                                "param": param,
                                "payload": payload,
                                "type": "sql_injection",
                                "confidence": "high",
                                "evidence": "SQL error detected",
                                "validated": True
                            })
                    else:
                        logger.debug(f"  [Mutation] Rejected SQL payload: no response change")
        
        elif vuln_type == "idor":
            payloads = mutations or self.generate_id_mutation(params[0])
            baseline_response = await self._send_request(url, method, {params[0]: "1"})
            
            seen_responses = {}
            
            for payload in payloads:
                test_params = {params[0]: payload}
                response = await self._send_request(url, method, test_params)
                
                if response:
                    validated = validator.validate_response(baseline_response, response, "idor")
                    if validated.get("confirmed"):
                        key = f"{response['status_code']}_{response['length']}"
                        
                        if response["status_code"] == 200 and key not in seen_responses:
                            results.append({
                                "param": params[0],
                                "payload": payload,
                                "type": "idor",
                                "confidence": "medium",
                                "evidence": f"unique response: {response['status_code']}",
                                "validated": True
                            })
                            seen_responses[key] = True
                    else:
                        logger.debug(f"  [Mutation] Rejected IDOR payload: no response change")
        
        elif vuln_type == "ssrf":
            payloads = mutations or self.generate_ssrf_payloads()
            
            for param in params:
                for payload in payloads:
                    test_params = {param: payload}
                    response = await self._send_request(url, method, test_params)
                    
                    if response:
                        validated = validator.validate_response(baseline, response, "ssrf")
                        if validated.get("confirmed"):
                            results.append({
                                "param": param,
                                "payload": payload,
                                "type": "ssrf",
                                "confidence": "high",
                                "evidence": "internal metadata leakage",
                                "validated": True
                            })
                    else:
                        logger.debug(f"  [Mutation] Rejected SSRF payload: no response change")

        elif vuln_type == "open_redirect":
            payloads = mutations or self.generate_open_redirect_payloads()

            for param in params:
                for payload in payloads:
                    test_params = {param: payload}
                    response = await self._send_request(url, method, test_params)

                    if response:
                        validated = validator.validate_response(baseline, response, "open_redirect")
                        if validated.get("confirmed") or response.get("status_code") in (301, 302, 303, 307, 308):
                            results.append({
                                "param": param,
                                "payload": payload,
                                "type": "open_redirect",
                                "confidence": "medium",
                                "evidence": f"redirect response: {response.get('status_code')}",
                                "validated": True,
                            })
                    else:
                        logger.debug(f"  [Mutation] Rejected open redirect payload: no response")

        elif vuln_type == "path_traversal":
            payloads = mutations or self.generate_path_traversal_payloads()

            for param in params:
                for payload in payloads:
                    test_params = {param: payload}
                    response = await self._send_request(url, method, test_params)

                    if response:
                        validated = validator.validate_response(baseline, response, "path_traversal")
                        if validated.get("confirmed"):
                            results.append({
                                "param": param,
                                "payload": payload,
                                "type": "path_traversal",
                                "confidence": "high",
                                "evidence": "path traversal confirmed",
                                "validated": True,
                            })
                    else:
                        logger.debug(f"  [Mutation] Rejected path traversal payload: no response")

        await self.close()
        return results
    
    async def _send_request(self, url, method, params, metadata=None):
        metadata = metadata or {}
        metadata["module"] = "mutation_engine"
        
        try:
            start_time = time.time()
            
            if self.exec_controller:
                if method == "GET":
                    response = await self.exec_controller.get(url, params=params, metadata=metadata)
                else:
                    response = await self.exec_controller.post(url, data=params, metadata=metadata)
                
                elapsed = time.time() - start_time
                
                if response and not response.error:
                    return {
                        "status_code": response.status_code,
                        "text": response.body,
                        "length": len(response.body) if response.body else 0,
                        "headers": response.headers,
                        "time": elapsed,
                        "url": url
                    }
            
            browser_headers = {"User-Agent": self.user_agent}
            fallback = ExecutionController(self.config)
            
            if method == "GET":
                response = await fallback.get(url, params=params, headers=browser_headers, metadata=metadata)
            else:
                response = await fallback.post(url, data=params, headers=browser_headers, metadata=metadata)
            
            await fallback.close()
            
            elapsed = time.time() - start_time
            
            if response and not response.error:
                return {
                    "status_code": response.status_code,
                    "text": response.body,
                    "length": len(response.body) if response.body else 0,
                    "headers": response.headers,
                    "time": elapsed,
                    "url": url
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"Mutation request error: {e}")
            return None
    
    def _detect_xss(self, response, payload):
        text = response.get("text", "")
        
        if payload in text:
            return True
        
        dangerous = ["<script", "onerror", "onload", "javascript:", "alert("]
        if any(d in text.lower() for d in dangerous):
            return True
        
        return False
    
    def _detect_sql_error(self, response):
        text = response.get("text", "").lower()
        
        sql_errors = [
            "sql syntax", "mysql", "postgresql", "ora-", "odbc", 
            "unterminated", "quoted string", "sql error", "warning:",
            "mysql_fetch", "sqlstate", "microsoft sql native error"
        ]
        
        return any(err in text for err in sql_errors)
    
    def get_mutation_strategy(self, param_name, param_value=None):
        mutations = []
        
        param_lower = param_name.lower()
        
        if any(x in param_lower for x in ["id", "user", "uid", "account"]):
            mutations.extend([
                ("id_enumeration", self.generate_id_mutation(param_name))
            ])
        
        if any(x in param_lower for x in ["search", "q", "query", "term", "text"]):
            mutations.extend([
                ("xss", self.generate_xss_payloads())
            ])
        
        if any(x in param_lower for x in ["id", "page", "sort", "order", "limit", "offset"]):
            mutations.extend([
                ("sql_error", self.generate_sql_payloads("error_based")),
                ("sql_blind", self.generate_sql_payloads("blind"))
            ])
        
        if any(x in param_lower for x in ["url", "redirect", "src", "dest", "link"]):
            mutations.extend([
                ("ssrf", self.generate_ssrf_payloads()),
                ("open_redirect", self.generate_open_redirect_payloads())
            ])
        
        if any(x in param_lower for x in ["file", "path", "doc", "template", "page"]):
            mutations.extend([
                ("path_traversal", self.generate_path_traversal_payloads())
            ])
        
        return mutations


async def run_mutation_tests(config, endpoint, vuln_type=None):
    engine = MutationEngine(config)
    
    if vuln_type:
        results = await engine.mutate_and_test(endpoint, vuln_type)
    else:
        results = []
        strategies = engine.get_mutation_strategy(
            endpoint.get("params", [""])[0]
        )
        
        for strategy_name, mutations in strategies:
            if mutations:
                strategy_results = await engine.mutate_and_test(endpoint, strategy_name, mutations)
                results.extend(strategy_results)
    
    return results