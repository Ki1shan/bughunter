import re
import time
import html
from modules.logging_config import logger
from modules.rag_loader import RAGLoader
from modules.execution_controller import get_execution_controller, ExecutionController


class VulnerabilityValidator:
    def __init__(self, config, rag_loader=None):
        self.config = config
        self.rag = rag_loader or RAGLoader("rag")
        if not self.rag.modules:
            self.rag.load_all()
        self.user_agent = config.get("user_agent", "BugHunter-AI/v2.0")
        self.timeout = config.get("request_timeout", 10)

        self.vuln_success_patterns = {}
        self.vuln_error_patterns = {}
        self.strong_patterns = {}
        self._load_rag_patterns()
        self._classify_pattern_strength()
        
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

    def _load_rag_patterns(self):
        for vuln_type in self.rag.get_all_vuln_types():
            advanced = self.rag.get_advanced_config(vuln_type)
            patterns_section = advanced.get("RESPONSE_PATTERNS", "")

            success_patterns = []
            error_patterns = []

            current_section = None
            for line in patterns_section.split("\n"):
                line = line.strip()
                if line.startswith("success_indicators"):
                    current_section = "success"
                    continue
                elif line.startswith("error_indicators"):
                    current_section = "error"
                    continue

                if line.startswith("-"):
                    pattern = line[1:].strip()
                    pattern = re.sub(r"\(.*?\)", "", pattern).strip()
                    if pattern:
                        if current_section == "success":
                            success_patterns.append(pattern.lower())
                        elif current_section == "error":
                            error_patterns.append(pattern.lower())

            if vuln_type == "sqli":
                success_patterns.extend([
                    "mysql", "postgresql", "sql syntax", "unterminated",
                    "quoted string", "sql error", "mysql_fetch",
                    "sqlstate", "microsoft sql native error"
                ])
                error_patterns.extend([
                    "syntax error near", "invalid sql", "bad sql grammar"
                ])

            if vuln_type == "xss":
                success_patterns.extend([
                    "<script", "onerror", "onload", "javascript:",
                    "alert(", "svg onload", "img src"
                ])

            if vuln_type == "ssrf":
                success_patterns.extend([
                    "169.254", "metadata", "ami-id", "instance-id",
                    "internal", "127.0.0.1", "localhost"
                ])

            if vuln_type == "command_injection":
                success_patterns.extend([
                    "uid=", "gid=", "whoami", "windows nt",
                    "directory of", "volume in drive", "uname"
                ])
                error_patterns.extend([
                    "command not found", "is not recognized",
                    "access denied", "permission denied"
                ])

            if vuln_type == "path_traversal":
                success_patterns.extend([
                    "/etc/passwd", "root:", "daemon:",
                    "boot.ini", "win.ini", "windows",
                    "directory listing", "parent directory"
                ])

            if vuln_type == "ssti":
                success_patterns.extend([
                    "jinja2", "mako", "django.template",
                    "freemarker", "twig", "velocity",
                    "{{7*7}}", "49", "{{config}}", "<class"
                ])

            if vuln_type == "deserialization":
                success_patterns.extend([
                    "java.io.serializable", "python object",
                    "rce detected", "gadget chain"
                ])

            self.vuln_success_patterns[vuln_type] = success_patterns
            self.vuln_error_patterns[vuln_type] = error_patterns

        logger.info(f"Loaded validation patterns for {len(self.vuln_success_patterns)} vuln types")

    def _classify_pattern_strength(self):
        strong_indicators = {
            "sqli": [
                "sql syntax", "mysql", "postgresql", "ora-", "sqlserver",
                "unterminated", "quoted string", "mysql_fetch", "sqlstate",
                "microsoft sql native error", "sql error",
                "syntax error near", "invalid sql", "bad sql grammar"
            ],
            "xss": [
                "<script", "onerror=", "onload=", "javascript:", "alert(",
                "<svg", "<img", "<iframe", "eval(", "document.cookie"
            ],
            "command_injection": [
                "uid=", "gid=", "whoami", "windows nt", "uname",
                "directory of", "volume in drive"
            ],
            "path_traversal": [
                "/etc/passwd", "root:", "daemon:", "boot.ini", "win.ini",
                "directory listing", "parent directory"
            ],
            "ssti": [
                "jinja2", "mako", "django.template", "freemarker",
                "twig", "velocity", "{{7*7}}", "{{config}}", "<class"
            ],
            "deserialization": [
                "java.io.serializable", "python object", "rce detected",
                "gadget chain"
            ],
            "ssrf": [
                "169.254", "ami-id", "instance-id", "metadata"
            ],
        }
        self.strong_patterns = strong_indicators

    def _get_strong_patterns(self, vuln_type):
        return self.strong_patterns.get(vuln_type, [])

    def _is_strong_pattern(self, vuln_type, pattern):
        return pattern in self._get_strong_patterns(vuln_type)

    def _evaluate_context_change(self, baseline_text, payload_text, vuln_type):
        context_signals = {
            "sqli": ["error", "exception", "syntax", "query", "database", "table", "column", "row", "result", "warning"],
            "xss": ["<script", "onerror", "onload", "javascript:", "alert(", "eval(", "document"],
            "ssti": ["template", "render", "jinja", "mako", "django", "freemarker"],
            "command_injection": ["cmd.exe", "powershell", "bash", "sh", "exec", "system"],
        }
        keywords = context_signals.get(vuln_type, [])
        baseline_lower = baseline_text.lower()
        payload_lower = payload_text.lower()
        new_keywords = []
        for kw in keywords:
            if kw in payload_lower and kw not in baseline_lower:
                new_keywords.append(kw)
        return new_keywords

    def _is_html_encoded(self, text, payload):
        """Check if dangerous characters from payload are HTML-encoded in response."""
        if not payload or not text:
            return False

        dangerous_chars = {
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": ("&#x27;", "&#39;", "&apos;"),
            "&": "&amp;",
            "`": ("&#x60;", "&#96;"),
        }

        encoded_count = 0
        total_dangerous = 0

        for char, encoded_forms in dangerous_chars.items():
            if char in payload:
                total_dangerous += 1
                if isinstance(encoded_forms, tuple):
                    if any(form in text for form in encoded_forms):
                        encoded_count += 1
                else:
                    if encoded_forms in text:
                        encoded_count += 1

        if total_dangerous == 0:
            return False

        return (encoded_count / total_dangerous) >= 0.8

    def _get_execution_context(self, payload_text, payload):
        """Analyze the execution context where payload is reflected.

        Returns a dict with:
          - context: 'script', 'event_handler', 'attribute', 'url', 'text', 'comment', 'unknown'
          - exploitable: bool indicating if this context allows XSS execution
          - barriers: list of encoding/sanitization barriers found
        """
        if not payload or not payload_text:
            return {"context": "unknown", "exploitable": False, "barriers": ["no_reflection"]}

        barriers = []
        payload_lower = payload.lower()
        text_lower = payload_text.lower()

        # Check if dangerous payload characters are HTML-encoded in the reflection
        # Compare payload-to-reflection, not entire response (which has HTML structure)
        payload_has_raw = False
        payload_has_encoded = False
        for char in ["<", ">", "\"", "'", "`"]:
            if char in payload:
                # Check if the char appears literally in the response (unencoded)
                # Find the reflection by searching for a unique non-encoded part of the payload
                safe_part = re.sub(r'[<>"\'`{}()]', '', payload)[:10].lower()
                if safe_part and safe_part in text_lower:
                    # Find position of reflection and check surrounding area for the char
                    idx = text_lower.find(safe_part)
                    window = text_lower[max(0, idx-30):idx+len(safe_part)+30]
                    if char in window:
                        payload_has_raw = True
                    encoded = html.escape(char)
                    if encoded in window:
                        payload_has_encoded = True
                else:
                    # Fallback: check globally but be conservative
                    if char in text_lower:
                        payload_has_raw = True
                    encoded = html.escape(char)
                    if encoded in payload_text:
                        payload_has_encoded = True

        if payload_has_encoded and not payload_has_raw:
            barriers.append("html_encoded")

        # Check for full HTML encoding of the payload
        encoded_payload = html.escape(payload)
        if encoded_payload in payload_text:
            return {"context": "encoded_text", "exploitable": False, "barriers": ["full_html_encoding"]}

        # Check for partial encoding (dangerous chars encoded)
        dangerous_in_payload = [c for c in ["<", ">", "\"", "'", "`"] if c in payload]
        if dangerous_in_payload:
            all_encoded = all(html.escape(c) in payload_text for c in dangerous_in_payload)
            if all_encoded and not payload_has_raw:
                return {"context": "encoded_text", "exploitable": False, "barriers": ["full_html_encoding"]}

        contexts = []

        if "<script" in text_lower:
            script_tags = list(re.finditer(r'<script[^>]*>(.*?)</script>', text_lower, re.DOTALL | re.IGNORECASE))
            for match in script_tags:
                if payload_lower in match.group(0).lower() or payload_lower in match.group(1).lower():
                    if any(b.startswith("html_encoded") for b in barriers):
                        return {"context": "script_but_encoded", "exploitable": False, "barriers": barriers}
                    return {"context": "script", "exploitable": True, "barriers": barriers}

        event_patterns = [
            r'on(?:error|load|click|mouseover|focus|blur|submit|change|input|keydown|keyup|keypress)\s*=\s*["\']?([^\s"\'>]+)',
        ]
        for pattern in event_patterns:
            for match in re.finditer(pattern, text_lower):
                if payload_lower in match.group(0):
                    if any(b.startswith("html_encoded") for b in barriers):
                        return {"context": "event_handler_but_encoded", "exploitable": False, "barriers": barriers}
                    return {"context": "event_handler", "exploitable": True, "barriers": barriers}

        attr_patterns = [
            r'(?:src|href|action|formaction|data|poster|background|dynsrc|lowsrc)\s*=\s*["\']?([^\s"\'>]*)',
            r'(?:style|css)\s*=\s*["\']?([^\s"\'>]*)',
        ]
        for pattern in attr_patterns:
            for match in re.finditer(pattern, text_lower):
                if payload_lower in match.group(0):
                    if any(b.startswith("html_encoded") for b in barriers):
                        return {"context": "attribute_but_encoded", "exploitable": False, "barriers": barriers}
                    attr_val = match.group(1)
                    if attr_val.startswith("javascript:"):
                        return {"context": "javascript_url", "exploitable": True, "barriers": barriers}
                    return {"context": "attribute", "exploitable": True, "barriers": barriers}

        if "<!--" in text_lower:
            comment_pattern = r'<!--(.*?)-->'
            for match in re.finditer(comment_pattern, text_lower, re.DOTALL):
                if payload_lower in match.group(1):
                    return {"context": "comment", "exploitable": False, "barriers": barriers + ["comment_context"]}

        tag_pattern = r'<[a-zA-Z][^>]*>'
        tags = list(re.finditer(tag_pattern, text_lower))
        for match in tags:
            if payload_lower in match.group(0):
                if any(b.startswith("html_encoded") for b in barriers):
                    return {"context": "tag_but_encoded", "exploitable": False, "barriers": barriers}
                return {"context": "tag", "exploitable": True, "barriers": barriers}

        return {"context": "text", "exploitable": False, "barriers": barriers + ["text_context_no_execution"]}

    def _check_csp_headers(self, headers):
        """Analyze Content-Security-Policy headers for XSS mitigation."""
        if not headers:
            return {"present": False, "strength": "none", "details": "no CSP headers"}

        csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
        if not csp:
            csp = headers.get("X-Content-Security-Policy", headers.get("x-content-security-policy", ""))
        if not csp:
            return {"present": False, "strength": "none", "details": "no CSP headers found"}

        csp_lower = csp.lower()
        strength = "weak"
        details = []

        if "script-src" in csp_lower:
            if "'none'" in csp_lower:
                strength = "strong"
                details.append("scripts completely disabled")
            elif "'self'" in csp_lower and "'unsafe-inline'" not in csp_lower:
                strength = "moderate"
                details.append("scripts limited to same-origin")
            elif "'unsafe-inline'" in csp_lower:
                details.append("unsafe-inline allows inline scripts")
            else:
                details.append("script-src directive present")
        else:
            details.append("no script-src directive")

        if "default-src" in csp_lower:
            if "'none'" in csp_lower:
                strength = "strong"
                details.append("default deny-all policy")
            elif "'self'" in csp_lower:
                details.append("default same-origin policy")

        if "object-src" in csp_lower and "'none'" in csp_lower:
            details.append("plugins/object disabled")

        return {"present": True, "strength": strength, "details": "; ".join(details)}

    def validate_response(self, baseline_response, payload_response, vuln_type, payload=""):
        def _make_result(tier, confirmed, confidence, reason, patterns):
            return {
                "confirmed": confirmed, "reason": reason, "confidence": confidence,
                "matched_patterns": patterns, "tier": tier,
                "suspected": tier == "suspected",
                "status_changed": status_changed,
                "length_diff": length_diff,
                "length_pct_change": round(length_pct_change, 1),
                "content_changed": True
            }

        if not baseline_response or not payload_response:
            return {"confirmed": False, "reason": "missing response data", "confidence": "none"}

        baseline_text = baseline_response.get("text", "")
        payload_text = payload_response.get("text", "")
        baseline_status = baseline_response.get("status_code", 0)
        payload_status = payload_response.get("status_code", 0)
        baseline_len = baseline_response.get("length", 0)
        payload_len = payload_response.get("length", 0)

        status_changed = baseline_status != payload_status
        length_diff = abs(payload_len - baseline_len)
        length_pct_change = (length_diff / baseline_len * 100) if baseline_len > 0 else 0

        content_changed = baseline_text.lower() != payload_text.lower()
        if not content_changed:
            logger.info(f"  [Validator] Rejected (no response change) for {vuln_type}")
            return {
                "confirmed": False, "reason": "no response change", "confidence": "none",
                "status_changed": status_changed, "length_diff": length_diff, "content_changed": False
            }

        payload_text_lower = payload_text.lower()
        baseline_text_lower = baseline_text.lower()

        if vuln_type == "xss" and payload:
            reflected = self._check_reflection(baseline_text, payload_text, payload)
            if reflected:
                encoded = self._is_html_encoded(payload_text, payload)
                if encoded:
                    logger.info(f"  [Validator] Rejected (HTML-encoded) for {vuln_type}: dangerous characters escaped")
                    return _make_result("rejected", False, "none", "payload reflected but HTML-encoded (not exploitable)", ["html_encoded_reflection"])

                ctx = self._get_execution_context(payload_text, payload)
                if not ctx["exploitable"]:
                    barrier_desc = ", ".join(ctx["barriers"])
                    logger.info(f"  [Validator] Rejected (safe context) for {vuln_type}: {ctx['context']} ({barrier_desc})")
                    return _make_result("rejected", False, "none", f"reflection in non-executable context ({ctx['context']})", [f"safe_context_{ctx['context']}"])

                csp = self._check_csp_headers(payload_response.get("headers", {}))
                confidence = "high"
                reason_parts = [f"dangerous XSS payload in executable context ({ctx['context']})"]
                if csp["present"]:
                    if csp["strength"] == "strong":
                        confidence = "medium"
                        reason_parts.append(f"CSP mitigates ({csp['details']})")
                    elif csp["strength"] == "moderate":
                        reason_parts.append(f"CSP partial mitigations ({csp['details']})")

                logger.info(f"  [Validator] Confirmed (strong evidence) for {vuln_type}: {reason_parts[0]} (CSP: {csp['strength']})")
                return {
                    "confirmed": True, "reason": "; ".join(reason_parts),
                    "confidence": confidence, "matched_patterns": ["xss_payload_reflection", f"context_{ctx['context']}"],
                    "execution_context": ctx["context"], "barriers": ctx["barriers"],
                    "csp": csp,
                    "status_changed": status_changed, "length_diff": length_diff,
                    "length_pct_change": round(length_pct_change, 1), "content_changed": True
                }

        success_patterns = self.vuln_success_patterns.get(vuln_type, [])
        error_patterns = self.vuln_error_patterns.get(vuln_type, [])

        matched_success = []
        matched_strong = []
        matched_weak = []
        for pattern in success_patterns:
            if pattern in payload_text_lower and pattern not in baseline_text_lower:
                matched_success.append(pattern)
                if self._is_strong_pattern(vuln_type, pattern):
                    matched_strong.append(pattern)
                else:
                    matched_weak.append(pattern)

        matched_error = []
        matched_error_strong = []
        for pattern in error_patterns:
            if pattern in payload_text_lower and pattern not in baseline_text_lower:
                matched_error.append(pattern)
                if self._is_strong_pattern(vuln_type, pattern):
                    matched_error_strong.append(pattern)

        all_new_keywords = self._evaluate_context_change(baseline_text, payload_text, vuln_type)

        if len(matched_strong) >= 1:
            logger.info(f"  [Validator] Confirmed (strong evidence) for {vuln_type}: strong pattern '{matched_strong[0]}'")
            return _make_result("confirmed", True, "high",
                f"strong indicator: {matched_strong[0]}", matched_strong)

        if len(matched_weak) >= 2:
            logger.info(f"  [Validator] Confirmed (strong evidence) for {vuln_type}: {len(matched_weak)} weak patterns")
            return _make_result("confirmed", True, "high",
                f"multiple indicators ({', '.join(matched_weak[:2])})", matched_weak)

        if vuln_type == "sqli" and len(matched_error_strong) >= 1:
            logger.info(f"  [Validator] Confirmed (strong evidence) for {vuln_type}: SQL error pattern '{matched_error_strong[0]}'")
            return _make_result("confirmed", True, "high",
                f"SQL error detected: {matched_error_strong[0]}", matched_error_strong)

        if vuln_type == "sqli":
            auth_indicators = ["welcome", "account", "balance", "logged in", "session", "dashboard", "my account"]
            auth_found = [a for a in auth_indicators if a in payload_text_lower and a not in baseline_text_lower]
            if auth_found and (length_pct_change >= 5 or status_changed):
                logger.info(f"  [Validator] Confirmed (strong evidence) for {vuln_type}: auth bypass ({', '.join(auth_found[:2])})")
                return _make_result("confirmed", True, "high",
                    f"authentication bypass via SQLi: {', '.join(auth_found[:2])}", auth_found)
            if auth_found and length_pct_change > 0:
                logger.info(f"  [Validator] Likely (moderate evidence) for {vuln_type}: possible auth bypass ({', '.join(auth_found[:2])})")
                return _make_result("likely", False, "medium",
                    f"possible auth bypass: {', '.join(auth_found[:2])}", auth_found)

        if vuln_type == "sqli" and all_new_keywords:
            logger.info(f"  [Validator] Likely (moderate evidence) for {vuln_type}: context keywords ({', '.join(all_new_keywords[:2])})")
            return _make_result("likely", False, "medium",
                f"SQL context change: {', '.join(all_new_keywords[:2])}", all_new_keywords)

        if status_changed and length_diff > 200:
            if matched_error:
                logger.info(f"  [Validator] Likely (moderate evidence) for {vuln_type}: status changed + error indicators")
                return _make_result("likely", False, "medium",
                    f"status changed with errors: {', '.join(matched_error[:2])}", matched_error)
            else:
                logger.info(f"  [Validator] Suspected (weak signal) for {vuln_type}: significant response change")
                return _make_result("suspected", False, "low",
                    "significant response change but no indicators", [])

        if len(matched_weak) == 1:
            if vuln_type == "sqli" and length_pct_change > 0:
                logger.info(f"  [Validator] Likely (moderate evidence) for {vuln_type}: single weak pattern + change ({length_pct_change:.1f}%)")
                return _make_result("likely", False, "medium",
                    f"weak indicator '{matched_weak[0]}' with {length_pct_change:.1f}% change", matched_weak)
            elif vuln_type in ["command_injection", "path_traversal", "ssti", "deserialization"] and length_pct_change > 1:
                logger.info(f"  [Validator] Likely (moderate evidence) for {vuln_type}: single weak pattern + change ({length_pct_change:.1f}%)")
                return _make_result("likely", False, "medium",
                    f"weak indicator '{matched_weak[0]}' with {length_pct_change:.1f}% change", matched_weak)

        if payload and payload in payload_text:
            reflected = self._check_reflection(baseline_text, payload_text, payload)
            if reflected:
                if vuln_type == "xss":
                    encoded = self._is_html_encoded(payload_text, payload)
                    if encoded:
                        logger.info(f"  [Validator] Rejected (HTML-encoded reflection) for {vuln_type}")
                        return _make_result("rejected", False, "none", "payload reflected but HTML-encoded", ["html_encoded_reflection"])
                    ctx = self._get_execution_context(payload_text, payload)
                    if not ctx["exploitable"]:
                        logger.info(f"  [Validator] Rejected (safe context) for {vuln_type}: {ctx['context']}")
                        return _make_result("rejected", False, "none", f"reflection in safe context ({ctx['context']})", [f"safe_context_{ctx['context']}"])
                    logger.info(f"  [Validator] Likely (moderate evidence) for {vuln_type}: executable context reflection (context={ctx['context']})")
                    return _make_result("likely", True, "medium", f"payload in executable context ({ctx['context']})", ["xss_reflection_executable"])
                elif length_pct_change >= 5:
                    logger.info(f"  [Validator] Likely (moderate evidence) for {vuln_type}: payload reflected + {length_pct_change:.1f}% change")
                    return _make_result("likely", False, "medium", f"payload reflected with {length_pct_change:.1f}% change", ["payload_reflection"])

        if length_pct_change < 1 and not status_changed and not matched_success and not matched_error:
            logger.info(f"  [Validator] Rejected (insufficient evidence) for {vuln_type}: trivial change ({length_pct_change:.1f}%)")
            return _make_result("rejected", False, "none",
                f"trivial change ({length_pct_change:.1f}%), no indicators", [])

        if all_new_keywords:
            logger.info(f"  [Validator] Suspected (weak signal) for {vuln_type}: context keywords only")
            return _make_result("suspected", False, "low",
                f"context change detected: {', '.join(all_new_keywords[:2])}", all_new_keywords)

        logger.info(f"  [Validator] Rejected (insufficient evidence) for {vuln_type}: no meaningful indicators")
        return _make_result("rejected", False, "none", "no meaningful validation indicators", [])

    def _check_reflection(self, baseline_text, payload_text, payload):
        if not payload:
            return False

        baseline_has = payload.lower() in baseline_text.lower()
        payload_has = payload.lower() in payload_text.lower()

        if payload_has and not baseline_has:
            return True

        dangerous_contexts = ["<script", "onerror", "onload", "javascript:", "alert(", "src=", "href="]
        for ctx in dangerous_contexts:
            baseline_count = baseline_text.lower().count(ctx)
            payload_count = payload_text.lower().count(ctx)
            if payload_count > baseline_count:
                return True

        return False

    async def validate_with_payload(self, endpoint, vuln_type, baseline_response, test_payload, param=None):
        await self.init_session()

        method = endpoint.get("method", "GET")
        url = endpoint.get("url", "")
        params = endpoint.get("params", [])

        if not params:
            await self.close()
            return {"confirmed": False, "reason": "no params available"}

        test_param = param or params[0]
        test_data = {test_param: test_payload}

        try:
            start_time = time.time()
            if method == "GET":
                resp = await self.session.get(url, params=test_data)
            else:
                resp = await self.session.post(url, data=test_data)
            elapsed = time.time() - start_time

            payload_response = {
                "status_code": resp.status_code,
                "text": resp.text,
                "length": len(resp.content),
                "headers": dict(resp.headers),
                "time": elapsed,
                "url": str(resp.url)
            }

            result = self.validate_response(baseline_response, payload_response, vuln_type, test_payload)
            result["param"] = test_param
            result["payload"] = test_payload
            result["response_time"] = elapsed

        except Exception as e:
            logger.debug(f"  [Validator] Request error: {e}")
            result = {"confirmed": False, "reason": f"request error: {e}", "confidence": "none"}

        await self.close()
        return result

    async def validate_time_based(self, endpoint, vuln_type, baseline_response, baseline_time=5.0, param=None):
        await self.init_session()

        method = endpoint.get("method", "GET")
        url = endpoint.get("url", "")
        params = endpoint.get("params", [])

        if not params:
            await self.close()
            return {"confirmed": False, "reason": "no params available"}

        test_param = param or params[0]
        time_payloads = ["sleep(5)", "; sleep 5", "| sleep 5", "&& sleep 5", "pg_sleep(5)"]

        best_result = {"confirmed": False, "reason": "no time delay detected", "confidence": "none"}

        for payload in time_payloads:
            test_data = {test_param: payload}

            try:
                start_time = time.time()
                if method == "GET":
                    resp = await self.session.get(url, params=test_data)
                else:
                    resp = await self.session.post(url, data=test_data)
                elapsed = time.time() - start_time

                if elapsed >= baseline_time - 1.0:
                    logger.info(f"  [Validator] Confirmed time-based ({vuln_type}): {elapsed:.1f}s delay with '{payload}'")
                    best_result = {
                        "confirmed": True,
                        "reason": f"time-based detection: {elapsed:.1f}s delay",
                        "confidence": "high",
                        "param": test_param,
                        "payload": payload,
                        "response_time": elapsed
                    }
                    break

            except Exception as e:
                logger.debug(f"  [Validator] Time-based test error: {e}")

        await self.close()
        return best_result

    async def init_session(self):
        if hasattr(self, 'session') and self.session:
            await self.session.aclose()
        self._session = None

    async def close(self):
        if hasattr(self, 'session') and self.session:
            await self.session.aclose()
            self._session = None
        
        if self._exec_controller:
            await self._exec_controller.close()
            self._exec_controller = None


def validate_response(baseline_response, payload_response, success_patterns=None):
    if not baseline_response or not payload_response:
        return False

    baseline_text = baseline_response.get("text", "")
    payload_text = payload_response.get("text", "")

    if payload_text == baseline_text:
        return False

    if success_patterns:
        payload_text_lower = payload_text.lower()
        for pattern in success_patterns:
            if pattern.lower() in payload_text_lower:
                return True

    return True
