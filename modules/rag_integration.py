import re
import json
import httpx
from modules.logging_config import logger
from modules.rag_loader import RAGLoader


class RAGIntegration:
    def __init__(self, config, rag_loader=None):
        self.config = config
        self.rag = rag_loader or RAGLoader("rag")
        if not self.rag.modules:
            self.rag.load_all()
        self.user_agent = config.get("user_agent", "BugHunter-AI/v2.0")
        self.timeout = config.get("request_timeout", 10)

    def get_vuln_type_from_params(self, params):
        if not params:
            return []

        detections = []
        for vuln_type in self.rag.get_all_vuln_types():
            triggers = self.rag.get_trigger_params(vuln_type)
            for level, trigger_items in triggers.items():
                for param in params:
                    param_lower = param.lower()
                    for trigger in trigger_items:
                        if trigger.lower() in param_lower:
                            detections.append({
                                "vuln_type": vuln_type,
                                "param": param,
                                "trigger": trigger,
                                "confidence_level": level
                            })
                            break

        return detections

    def get_vuln_type_from_response(self, response_text, response_headers=None):
        detections = []
        text_lower = response_text.lower()

        for vuln_type in self.rag.get_all_vuln_types():
            response_patterns = self.rag.get_response_patterns(vuln_type)
            for pattern_name, pattern_value in response_patterns.items():
                if pattern_value.lower() in text_lower:
                    detections.append({
                        "vuln_type": vuln_type,
                        "pattern": pattern_name,
                        "matched": pattern_value
                    })

        db_fingerprinting = self.rag.get_database_fingerprinting()
        for db_name, indicators in db_fingerprinting.items():
            for indicator in indicators:
                if indicator.lower() in text_lower:
                    detections.append({
                        "vuln_type": "sqli",
                        "database": db_name,
                        "indicator": indicator
                    })

        xml_parser_fps = self.rag.get_xml_parser_fingerprinting()
        for parser_name, indicators in xml_parser_fps.items():
            for indicator in indicators:
                if indicator.lower() in text_lower:
                    detections.append({
                        "vuln_type": "xxe",
                        "parser": parser_name,
                        "indicator": indicator
                    })

        template_fps = self.rag.get_template_engine_fingerprinting()
        for engine_name, indicators in template_fps.items():
            for indicator in indicators:
                if indicator.lower() in text_lower:
                    detections.append({
                        "vuln_type": "ssti",
                        "engine": engine_name,
                        "indicator": indicator
                    })

        return detections

    def evaluate_decision_rules(self, vuln_type, context):
        rules = self.rag.get_decision_rules(vuln_type)
        triggered_rules = []

        for rule_id, rule_data in rules.items():
            if not isinstance(rule_data, dict) or not rule_id.startswith("R"):
                continue

            triggered = False
            confidence = rule_data.get("confidence", 0)

            if "trigger_items" in rule_data:
                params = context.get("params", [])
                endpoint = context.get("endpoint", "").lower()
                for trigger in rule_data["trigger_items"]:
                    for param in params:
                        if trigger.lower() in param.lower() or trigger.lower() in endpoint:
                            triggered = True
                            break
                    if triggered:
                        break

            if "trigger_condition" in rule_data:
                condition = rule_data["trigger_condition"]
                if condition in context:
                    triggered = True

            if "trigger_contains" in rule_data:
                tech_stack = context.get("tech_stack", "").lower()
                for trigger in rule_data["trigger_contains"]:
                    if trigger.lower() in tech_stack:
                        triggered = True
                        break

            if triggered:
                raw_output = rule_data.get("output", "")
                param_list = ", ".join(context.get("params", []))
                context_map = {
                    "context": param_list if param_list else "parameter",
                    "param": context.get("params", [""])[0] if context.get("params") else "",
                    "endpoint": context.get("endpoint", ""),
                    "method": context.get("method", ""),
                    "params": param_list,
                }
                try:
                    output = raw_output.format(**context_map)
                except (KeyError, IndexError):
                    output = raw_output.replace("{context}", param_list or "parameter")

                triggered_rules.append({
                    "rule_id": rule_id,
                    "rule_name": rule_data.get("name", ""),
                    "decision": rule_data.get("decision", ""),
                    "priority": rule_data.get("priority", 5),
                    "confidence": confidence,
                    "output": output
                })

        triggered_rules.sort(key=lambda r: r.get("priority", 5))
        return triggered_rules

    def build_detection_context(self, endpoint, response=None):
        context = {
            "endpoint": endpoint.get("url", ""),
            "params": endpoint.get("params", []),
            "method": endpoint.get("method", "GET"),
        }

        if response:
            context["response_text"] = response.get("text", "")
            context["status_code"] = response.get("status_code", 0)
            context["headers"] = response.get("headers", {})
            context["response_length"] = response.get("length", 0)

        return context

    def detect_vulnerabilities(self, endpoint, response=None):
        findings = []
        context = self.build_detection_context(endpoint, response)

        BENIGN_PARAMS = {
            'page','limit','offset','size','count','per_page',
            'sort','order','direction','lang','locale','timezone',
            'name','bio','description','label','email','phone',
            'age','gender','format','type','version','color',
            'theme','style','debug','verbose','pretty','date','author',
            'first_name','last_name','display_name','username','nickname',
            'handle','avatar','about'
        }

        param_detections = self.get_vuln_type_from_params(context.get("params", []))
        for det in param_detections:
            vuln_type = det["vuln_type"]
            confidence_level = det["confidence_level"]
            confidence_map = {"high_confidence": 75, "medium_confidence": 60, "low_confidence": 40}
            base_confidence = confidence_map.get(confidence_level, 50)

            decision_rules = self.evaluate_decision_rules(vuln_type, context)
            for rule in decision_rules:
                param = det["param"]
                if param in BENIGN_PARAMS and rule.get('priority', 2) >= 2:
                    continue
                if rule.get("priority", 2) == 1:
                    adjusted_confidence = min(85, base_confidence + rule["confidence"] // 2)
                elif rule.get("priority", 2) == 2:
                    adjusted_confidence = min(40, base_confidence + rule["confidence"] // 4)
                else:
                    adjusted_confidence = min(30, rule["confidence"] // 4)
                findings.append({
                    "type": vuln_type,
                    "param": det["param"],
                    "reason": rule["output"],
                    "confidence": "high" if adjusted_confidence >= 75 else "medium" if adjusted_confidence >= 50 else "low",
                    "confidence_score": adjusted_confidence,
                    "rule_id": rule["rule_id"],
                    "priority": rule["priority"],
                    "rag_triggered": True
                })

        if response:
            response_detections = self.get_vuln_type_from_response(
                response.get("text", ""), response.get("headers", {})
            )
            for det in response_detections:
                findings.append({
                    "type": det["vuln_type"],
                    "reason": f"Response pattern matched: {det.get('indicator', det.get('pattern', 'unknown'))}",
                    "confidence": "high",
                    "confidence_score": 85,
                    "rag_triggered": True
                })

        seen = set()
        unique_findings = []
        for f in findings:
            key = f"{f.get('type')}-{f.get('param', '')}-{f.get('reason', '')[:30]}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def get_rag_payloads_for_vuln(self, vuln_type, context=None):
        payloads = self.rag.get_test_payloads(vuln_type)

        if vuln_type == "sqli":
            payloads.extend(self.rag.get_sqli_safe_payloads())
            for i, p in enumerate(self.rag.get_no_sql_payloads()):
                payloads.append({"name": f"nosql_{i}", "value": p})
            for i, p in enumerate(self.rag.get_ldap_payloads()):
                payloads.append({"name": f"ldap_{i}", "value": p})
        elif vuln_type == "xss":
            payloads.extend(self.rag.get_test_payloads("xss"))
            payloads.extend(self.rag.get_xss_safe_payloads())
        elif vuln_type == "ssrf":
            payloads.extend(self.rag.get_ssrf_safe_payloads())
            for svc in self.rag.get_internal_service_targets():
                payloads.append({"name": f"internal_{svc['type']}", "value": svc["payload"]})
        elif vuln_type == "path_traversal":
            os_type = "windows" if context and context.get("os", "linux") == "windows" else "linux"
            payloads.extend(self.rag.get_path_traversal_safe_payloads(os_type))
        elif vuln_type == "xxe":
            payloads.extend([{"name": "blind_xxe", "value": p} for p in self.rag.get_blind_xxe_payloads()])
            payloads.extend([{"name": "soap_xxe", "value": p} for p in self.rag.get_soap_xxe_payloads()])
            payloads.extend([{"name": "svg_xxe", "value": p} for p in self.rag.get_svg_xxe_payloads()])
        elif vuln_type == "graphql":
            return [
                {'name': 'introspection', 'value': '{__schema{types{name}}}', 'category': 'recon'},
                {'name': 'field_suggestion', 'value': '{__typename}', 'category': 'probe'},
                {'name': 'batch_query', 'value': '[{"query":"{__typename}"},{"query":"{__typename}"}]', 'category': 'dos'},
            ]
        elif vuln_type == "csrf":
            return [
                {'name': 'no_token', 'value': 'remove_csrf_token', 'category': 'bypass'},
                {'name': 'wrong_token', 'value': 'invalid_csrf_token_12345', 'category': 'bypass'},
            ]
        elif vuln_type == "idor":
            return [
                {'name': 'increment_id', 'value': '+1', 'category': 'enumeration'},
                {'name': 'decrement_id', 'value': '-1', 'category': 'enumeration'},
                {'name': 'zero_id', 'value': '0', 'category': 'enumeration'},
                {'name': 'negative_id', 'value': '-999', 'category': 'enumeration'},
            ]
        elif vuln_type == "jwt":
            return [
                {'name': 'none_alg', 'value': 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.', 'category': 'alg_bypass'},
                {'name': 'empty_secret', 'value': '', 'category': 'weak_secret', '_is_valid': True},
            ]
        elif vuln_type == "race_conditions":
            return [
                {'name': 'parallel_request', 'value': 'RACE_CONDITION_TEST', 'category': 'timing'},
            ]

        seen = set()
        deduped = []
        for p in payloads:
            if p.get('name') not in seen:
                seen.add(p.get('name'))
                deduped.append(p)
        return deduped

    def _is_payload_broken(self, p):
        val = p.get('value', '')
        valid_single_chars = ["'", '"', '`']
        return not p.get('_is_valid') and not val in valid_single_chars and not val.strip()

    def get_rag_context_for_ai(self, vuln_types, endpoint=None):
        context_parts = []

        for vuln_type in vuln_types:
            detection = self.rag.get_detection_config(vuln_type)
            if detection:
                test_method = detection.get("TEST_METHOD", "")
                if test_method:
                    context_parts.append(f"[{vuln_type.upper()} TEST METHOD]\n{test_method}")

            advanced = self.rag.get_advanced_config(vuln_type)
            if advanced:
                edge_cases = self.rag.get_edge_cases(vuln_type)
                if edge_cases:
                    edge_summary = "\n".join([f"- {ec['name']}" for ec in edge_cases[:5]])
                    context_parts.append(f"[{vuln_type.upper()} EDGE CASES]\n{edge_summary}")

            response_patterns = self.rag.get_response_patterns(vuln_type)
            if response_patterns:
                context_parts.append(f"[{vuln_type.upper()} RESPONSE PATTERNS]\n{json.dumps(response_patterns, indent=2)}")

        if not context_parts:
            return None

        return "\n\n".join(context_parts)

    def get_rag_decision_summary(self, vuln_type):
        rules = self.rag.get_decision_rules(vuln_type)
        active_rules = {k: v for k, v in rules.items() if isinstance(v, dict) and k.startswith("R")}

        summary = {
            "vuln_type": vuln_type,
            "total_rules": len(active_rules),
            "rules": []
        }

        for rule_id, rule_data in sorted(active_rules.items(), key=lambda x: x[1].get("priority", 5)):
            summary["rules"].append({
                "id": rule_id,
                "name": rule_data.get("name", ""),
                "priority": rule_data.get("priority", 5),
                "confidence": rule_data.get("confidence", 0),
                "decision": rule_data.get("decision", "")
            })

        return summary

    def get_rag_output_template(self, vuln_type, param="", test_payload="", confidence=0, remaining=""):
        template = self.rag.get_output_template(vuln_type)
        if not template:
            return None

        template = template.replace("{param}", param)
        template = template.replace("{test_payload}", test_payload)
        template = template.replace("{confidence}", str(confidence))
        template = template.replace("{remaining}", remaining)

        detection = self.rag.get_detection_config(vuln_type)
        reasons = detection.get("DETECTION_CONDITIONS", "")
        template = template.replace("{detection_reason}", f"{vuln_type} indicators detected")

        return template

    def get_rag_learning_config(self, vuln_type):
        return {
            "decay_config": self.rag.get_learning_config(vuln_type).get("DECAY_CONFIG", ""),
            "success_patterns": self.rag.get_success_patterns(vuln_type),
            "failure_patterns": self.rag.get_failure_patterns(vuln_type),
            "retest_conditions": self.rag.get_retest_logic(vuln_type),
            "bypass_suggestions": self.rag.get_bypass_suggestions(vuln_type),
            "waf_bypasses": self.rag.get_waf_bypass_suggestions(vuln_type)
        }

    def get_cloud_metadata_payloads(self):
        cloud_config = self.rag.get_cloud_provider_config()
        payloads = []

        for section_name, content in cloud_config.items():
            type_matches = re.findall(r"- type:\s*(.+?)\s*\n\s+payload:\s*[\"'](.+?)[\"']", content)
            for ptype, payload in type_matches:
                payloads.append({
                    "cloud": section_name.split("_")[0].lower(),
                    "type": ptype,
                    "payload": payload
                })

        return payloads

    def get_internal_scan_targets(self):
        targets = []
        for ip_range in self.rag.get_internal_ip_ranges():
            targets.append(ip_range)

        jwt_fps = self.rag.get_jwt_fingerprinting()
        for ep in jwt_fps.get("jwks_endpoints", []):
            targets.append(ep)

        return targets

    def get_rag_enhanced_prompt(self, endpoint, findings):
        vuln_types = list(set(f.get("type", "") for f in findings if f.get("type")))
        rag_context = self.get_rag_context_for_ai(vuln_types, endpoint)

        if not rag_context:
            return None

        prompt = f"""RAG KNOWLEDGE BASE CONTEXT FOR {endpoint.get('url', 'UNKNOWN')}:

{rag_context}

Use the above RAG context to provide more specific and actionable security recommendations.
Reference specific edge cases, payloads, and detection patterns from the RAG knowledge base."""

        return prompt

    def get_rag_confidence_adjustment(self, vuln_type, base_confidence, context=None):
        scoring = self.rag.get_confidence_scoring(vuln_type)
        if not scoring:
            return base_confidence

        adjusted = base_confidence

        boost_items = scoring.get("boost_items", "")
        if boost_items:
            boost_keywords = ["internal_ip", "cloud_metadata", "localhost", "connection_error"]
            for keyword in boost_keywords:
                if keyword in boost_items.lower() and context and keyword in str(context).lower():
                    adjusted = min(95, adjusted + 15)

        reduce_items = scoring.get("reduce_items", "")
        if reduce_items:
            reduce_keywords = ["whitelist", "restricted", "false_positive"]
            for keyword in reduce_keywords:
                if keyword in reduce_items.lower() and context and keyword in str(context).lower():
                    adjusted = max(10, adjusted - 20)

        return adjusted


async def run_rag_detection(config, endpoint, response=None):
    rag = RAGIntegration(config)
    return rag.detect_vulnerabilities(endpoint, response)
