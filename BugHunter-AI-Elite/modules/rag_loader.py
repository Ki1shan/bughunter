import json
import os
import re
from pathlib import Path
from modules.logging_config import logger


class RAGLoader:
    def __init__(self, rag_dir="rag"):
        self.rag_dir = Path(rag_dir)
        self.modules = {}
        self.decision_rules = {}
        self.detection_patterns = {}
        self.learning_configs = {}
        self.advanced_configs = {}
        self.vuln_types = set()

    def load_all(self):
        if not self.rag_dir.exists():
            logger.warning(f"RAG directory not found: {self.rag_dir}")
            return

        txt_files = list(self.rag_dir.glob("*.txt"))
        logger.info(f"Loading {len(txt_files)} RAG files...")

        for f in txt_files:
            try:
                self._parse_file(f)
            except Exception as e:
                logger.error(f"Error parsing RAG file {f.name}: {e}")

        logger.info(f"RAG loaded: {len(self.modules)} modules, {len(self.decision_rules)} rule sets, {len(self.detection_patterns)} detection configs")
        return self


    def load_from_json(self, json_path="rag_knowledge.json"):
        """Load all RAG content from merged rag_knowledge.json (GitHub-friendly single file)."""
        import json
        from pathlib import Path
        p = Path(json_path)
        if not p.exists():
            return self.load_all()  # fallback to individual files
        with open(p, 'r', encoding='utf-8') as f:
            data = json.load(f)
        import tempfile, os
        tmp_dir = Path(tempfile.mkdtemp())
        for key, text in data.items():
            (tmp_dir / f"{key}.txt").write_text(text, encoding='utf-8')
        self.rag_dir = tmp_dir
        self.load_all()
        return self

    def _parse_file(self, filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        filename = filepath.stem
        category_keywords = ["advanced", "detection", "decision_rules", "learning"]
        
        vuln_type = None
        file_category = None
        
        for keyword in category_keywords:
            if filename.endswith(f"_{keyword}"):
                vuln_type = filename[:-(len(keyword) + 1)]
                file_category = keyword
                break
        
        if not vuln_type:
            return
        self.vuln_types.add(vuln_type)

        sections = self._split_sections(content)

        if file_category == "advanced":
            self.advanced_configs[vuln_type] = sections
        elif file_category == "decision_rules":
            self.decision_rules[vuln_type] = self._parse_rules(sections)
        elif file_category == "detection":
            self.detection_patterns[vuln_type] = sections
        elif file_category == "learning":
            self.learning_configs[vuln_type] = sections

        module_name = sections.get("MODULE", vuln_type.upper())
        if module_name not in self.modules:
            self.modules[module_name] = {
                "vuln_type": vuln_type,
                "categories": {},
                "sections": {}
            }
        self.modules[module_name]["categories"][file_category] = True
        self.modules[module_name]["sections"].update(sections)

    def _split_sections(self, content):
        sections = {}
        current_section = None
        current_content = []

        for line in content.split("\n"):
            section_match = re.match(r"^\[([A-Z_][A-Z0-9_\s\(\)\-→]*)\]", line)
            if section_match:
                if current_section:
                    sections[current_section] = "\n".join(current_content).strip()
                current_section = section_match.group(1).strip()
                current_content = []
            elif line.startswith("===") or line.strip() == "":
                if current_content and current_content[-1].strip() == "" and line.strip() == "":
                    continue
                current_content.append(line)
            else:
                current_content.append(line)

        if current_section:
            sections[current_section] = "\n".join(current_content).strip()

        return sections

    def _parse_rules(self, sections):
        rules = {}
        rules_text = sections.get("RULES", "")

        rule_pattern = re.compile(r"(R\d+):\s*\n((?:.*\n)*?)(?=\nR\d+:|$)", re.MULTILINE)
        for match in rule_pattern.finditer(rules_text):
            rule_id = match.group(1)
            rule_body = match.group(2).strip()

            rule_data = {"id": rule_id}
            for line in rule_body.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()

                    if key == "trigger":
                        if " IN [" in value:
                            items_match = re.search(r"IN \[(.+?)\]", value)
                            if items_match:
                                items = [i.strip().strip("\"").strip("'") for i in items_match.group(1).split(",")]
                                rule_data["trigger_items"] = items
                        elif " = true" in value:
                            rule_data["trigger_condition"] = value.replace(" = true", "").strip()
                        elif " CONTAINS " in value:
                            items_match = re.search(r"CONTAINS \[(.+?)\]", value)
                            if items_match:
                                items = [i.strip().strip("\"").strip("'") for i in items_match.group(1).split(",")]
                                rule_data["trigger_contains"] = items
                        else:
                            rule_data["trigger_condition"] = value
                    elif key == "decision":
                        rule_data["decision"] = value
                    elif key == "priority":
                        try:
                            rule_data["priority"] = int(value)
                        except ValueError:
                            rule_data["priority"] = value
                    elif key == "confidence":
                        try:
                            rule_data["confidence"] = int(value)
                        except ValueError:
                            rule_data["confidence"] = value
                    elif key == "output":
                        rule_data["output"] = value.strip("\"").strip("'")
                    elif key == "name":
                        rule_data["name"] = value

            rules[rule_id] = rule_data

        confidence_section = sections.get("CONFIDENCE_THRESHOLDS", "")
        thresholds = {}
        for line in confidence_section.split("\n"):
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                try:
                    thresholds[key.strip()] = int(value.strip())
                except ValueError:
                    thresholds[key.strip()] = value.strip()
        if thresholds:
            rules["thresholds"] = thresholds

        priority_section = sections.get("PRIORITY_MAPPING", "")
        priority_mapping = {}
        for line in priority_section.split("\n"):
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                try:
                    priority_mapping[int(key.strip())] = value.strip().strip("\"").strip("'")
                except ValueError:
                    pass
        if priority_mapping:
            rules["priority_mapping"] = priority_mapping

        return rules

    def get_detection_config(self, vuln_type):
        return self.detection_patterns.get(vuln_type, {})

    def get_decision_rules(self, vuln_type):
        return self.decision_rules.get(vuln_type, {})

    def get_advanced_config(self, vuln_type):
        return self.advanced_configs.get(vuln_type, {})

    def get_learning_config(self, vuln_type):
        return self.learning_configs.get(vuln_type, {})

    def get_all_vuln_types(self):
        return list(self.vuln_types)

    def get_trigger_params(self, vuln_type):
        detection = self.get_detection_config(vuln_type)
        triggers = {}

        detection_text = detection.get("DETECTION_CONDITIONS", "")
        trigger_params_match = re.search(r"trigger_params:\s*\n((?:.*\n)*?)(?=\n\s{0,3}\[|\n\w|\Z)", detection_text)
        if trigger_params_match:
            block = trigger_params_match.group(1)
            confidence_levels = re.findall(r"(high_confidence|medium_confidence|low_confidence):\s*\n((?:\s+- .*\n?)+)", block)
            for level, items_block in confidence_levels:
                items = []
                for item_line in items_block.strip().split("\n"):
                    item_line = item_line.strip()
                    if item_line.startswith("-"):
                        item_line = item_line[1:].strip()
                        parsed = [i.strip() for i in item_line.split(",")]
                        items.extend(parsed)
                triggers[level] = items

        decision = self.get_decision_rules(vuln_type)
        for rule_id, rule_data in decision.items():
            if isinstance(rule_data, dict) and rule_id.startswith("R"):
                if "trigger_items" in rule_data:
                    if "high_confidence" not in triggers:
                        triggers["high_confidence"] = []
                    triggers["high_confidence"].extend(rule_data["trigger_items"])

        return triggers

    def get_confidence_scoring(self, vuln_type):
        detection = self.get_detection_config(vuln_type)
        scoring = {}

        scoring_text = detection.get("CONFIDENCE_SCORING", "")
        base_match = re.search(r"base_confidence:\s*(\d+)", scoring_text)
        if base_match:
            scoring["base_confidence"] = int(base_match.group(1))

        boost_items = re.findall(r"boost_if:\s*\n((?:\s+-?.*\n?)+)", scoring_text)
        if boost_items:
            scoring["boost_items"] = boost_items[0].strip()

        reduce_items = re.findall(r"reduce_if:\s*\n((?:\s+-?.*\n?)+)", scoring_text)
        if reduce_items:
            scoring["reduce_items"] = reduce_items[0].strip()

        return scoring

    def get_edge_cases(self, vuln_type):
        advanced = self.get_advanced_config(vuln_type)
        edge_cases = []

        for section_name, section_content in advanced.items():
            if section_name.startswith("EDGE_CASE"):
                edge_cases.append({
                    "name": section_name,
                    "content": section_content
                })

        return edge_cases

    def get_test_payloads(self, vuln_type):
        detection = self.get_detection_config(vuln_type)
        payloads = []

        KNOWN_SINGLE_CHAR_PAYLOADS = {
            'single_quote': "'",
            'double_quote': '"',
            'backtick': '`',
            'empty_secret': '',
        }

        test_method = detection.get("TEST_METHOD", "")
        safe_payloads_match = re.search(r"safe_payloads:\s*\n((?:.*\n)*?)(?=\n\s{0,3}\[|\nmax_|\n\w{2,}[^a-z])", test_method)
        if safe_payloads_match:
            block = safe_payloads_match.group(1)
            payload_blocks = re.findall(r"- name:\s*(.+?)\s*\n\s+value:\s*[\"'](.+?)[\"']\s*(?:\n\s+expected:\s*[\"']?(.+?)[\"']?)?(?:\n\s+note:\s*[\"']?(.+?)[\"']?)?", block)
            for name, value, expected, note in payload_blocks:
                payloads.append({
                    "name": name.strip(),
                    "value": value.strip(),
                    "expected": expected.strip() if expected else None,
                    "note": note.strip() if note else None
                })

        for p in payloads:
            if not p.get('value', '').strip() and p.get('name') in KNOWN_SINGLE_CHAR_PAYLOADS:
                p['value'] = KNOWN_SINGLE_CHAR_PAYLOADS[p['name']]
                p['_is_valid'] = True

        seen = set()
        deduped = []
        for p in payloads:
            if p['name'] not in seen:
                seen.add(p['name'])
                deduped.append(p)
        return deduped

    def get_response_patterns(self, vuln_type):
        advanced = self.get_advanced_config(vuln_type)
        patterns_section = advanced.get("RESPONSE_PATTERNS", "")

        patterns = {}
        for line in patterns_section.split("\n"):
            line = line.strip()
            if ":" in line and not line.startswith("-"):
                key, value = line.split(":", 1)
                patterns[key.strip()] = value.strip()

        return patterns

    def get_priority_mapping(self, vuln_type):
        decision = self.get_decision_rules(vuln_type)
        return decision.get("priority_mapping", {})

    def get_retest_logic(self, vuln_type):
        learning = self.get_learning_config(vuln_type)
        retest_section = learning.get("RETEST_LOGIC", "")

        conditions = []
        for line in retest_section.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                conditions.append(line[1:].strip())

        return conditions

    def get_success_patterns(self, vuln_type):
        learning = self.get_learning_config(vuln_type)
        patterns = {}

        for section_name, content in learning.items():
            if section_name.startswith("SUCCESS_PATTERNS") or section_name.startswith("pattern_"):
                patterns[section_name] = content

        return patterns

    def get_failure_patterns(self, vuln_type):
        learning = self.get_learning_config(vuln_type)
        patterns = {}

        for section_name, content in learning.items():
            if section_name.startswith("FAILURE_PATTERNS") or section_name.startswith("pattern_"):
                if "failure" in section_name.lower() or "failure" in content.lower():
                    patterns[section_name] = content

        return patterns

    def get_output_template(self, vuln_type):
        detection = self.get_detection_config(vuln_type)
        output_section = detection.get("OUTPUT_TEMPLATE", "")

        format_match = re.search(r"format:\s*\|((?:\n.*)+?)(?=example:|\[)", output_section, re.DOTALL)
        if format_match:
            return format_match.group(1).strip()

        example_match = re.search(r"example:\s*\|((?:\n.*)+?)(?=\[|\Z)", output_section, re.DOTALL)
        if example_match:
            return example_match.group(1).strip()

        return ""

    def get_tools_integration(self, vuln_type):
        advanced = self.get_advanced_config(vuln_type)
        tools_section = advanced.get("TOOLS_FOR_RACE_CONDITIONS", "") or advanced.get("XXE_TOOLS", "") or advanced.get("JWT_TOOLS_INTEGRATION", "")

        tools = []
        if tools_section:
            tool_matches = re.findall(r"- name:\s*(.+?)\s*\n\s+usage:\s*(.+?)(?:\s*\n\s+commands:)?", tools_section)
            for name, usage in tool_matches:
                tools.append({"name": name.strip(), "usage": usage.strip()})

            command_matches = re.findall(r"- \"(.*?)\"", tools_section)
            if command_matches:
                for cmd in command_matches:
                    tools.append({"command": cmd})

        return tools

    def get_cloud_provider_config(self):
        ssrf_advanced = self.get_advanced_config("ssrf")
        cloud_config = {}

        for section_name, content in ssrf_advanced.items():
            if "AWS" in section_name or "GCP" in section_name or "AZURE" in section_name:
                cloud_config[section_name] = content

        return cloud_config

    def get_database_fingerprinting(self):
        sqli_advanced = self.get_advanced_config("sqli")
        fingerprinting = {}

        fingerprint_section = sqli_advanced.get("DATABASE_FINGERPRINTING", "")
        for line in fingerprint_section.split("\n"):
            line = line.strip()
            if line.endswith("_indicators:"):
                db_name = line.replace("_indicators:", "")
                fingerprinting[db_name] = []
            elif line.startswith("-") and fingerprinting:
                last_db = list(fingerprinting.keys())[-1]
                fingerprinting[last_db].append(line[1:].strip().strip("\""))

        return fingerprinting

    def get_xml_parser_fingerprinting(self):
        xxe_learning = self.get_learning_config("xxe")
        parsers = {}

        for section_name, content in xxe_learning.items():
            if "parser_indicators" in section_name:
                parser_name = section_name.replace("_indicators", "")
                indicators = []
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith("-"):
                        indicators.append(line[1:].strip().strip("\""))
                parsers[parser_name] = indicators

        return parsers

    def get_template_engine_fingerprinting(self):
        ssti_advanced = self.get_advanced_config("ssti")
        engines = {}

        fingerprint_section = ssti_advanced.get("TEMPLATE_ENGINE_FINGERPRINTING", "")
        for line in fingerprint_section.split("\n"):
            line = line.strip()
            if line.endswith("_indicators:"):
                engine_name = line.replace("_indicators", "")
                engines[engine_name] = []
            elif line.startswith("-") and engines:
                last_engine = list(engines.keys())[-1]
                engines[last_engine].append(line[1:].strip().strip("\""))

        return engines

    def get_jwt_fingerprinting(self):
        jwt_learning = self.get_learning_config("jwt")
        fingerprinting = {}

        jwks_section = jwt_learning.get("JWT_FINGERPRINTING", "")
        for line in jwks_section.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                if "jwks_endpoints" not in fingerprinting:
                    fingerprinting["jwks_endpoints"] = []
                fingerprinting["jwks_endpoints"].append(line[1:].strip().strip("\""))
            elif line.startswith("https://"):
                if "common_issuers" not in fingerprinting:
                    fingerprinting["common_issuers"] = []
                fingerprinting["common_issuers"].append(line.strip().strip("\""))

        return fingerprinting

    def get_internal_ip_ranges(self):
        ssrf_advanced = self.get_advanced_config("ssrf")
        ip_section = ssrf_advanced.get("INTERNAL_IP_RANGES", "")

        ranges = []
        for line in ip_section.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                ip_match = re.search(r"\"(.+?)\"", line)
                if ip_match:
                    ranges.append(ip_match.group(1))

        return ranges

    def get_common_weak_secrets(self):
        jwt_decision = self.get_decision_rules("jwt")
        secrets_section = jwt_decision.get("COMMON_WEAK_SECRETS", "") or jwt_decision.get("precomputed_list", "")

        secrets = []
        for line in secrets_section.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                secret = line[1:].strip().strip("\"").strip("'")
                secrets.append(secret)

        return secrets

    def get_waf_bypass_suggestions(self, vuln_type):
        learning = self.get_learning_config(vuln_type)
        bypass_section = learning.get("WAF_BYPASS_SUGGESTIONS", "")

        bypasses = {}
        current_db = None
        for line in bypass_section.split("\n"):
            line = line.strip()
            if line.startswith("when_") and line.endswith(":"):
                current_db = line.replace("when_", "").replace(":", "")
                bypasses[current_db] = []
            elif line.startswith("-") and current_db:
                bypasses[current_db].append(line[1:].strip())

        return bypasses

    def get_bypass_suggestions(self, vuln_type):
        learning = self.get_learning_config(vuln_type)
        bypass_section = learning.get("BYPASS_SUGGESTION", "")

        suggestions = []
        for line in bypass_section.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                suggestions.append(line[1:].strip())

        return suggestions

    def get_chaining_opportunities(self, vuln_type):
        learning = self.get_learning_config(vuln_type)
        chain_section = learning.get("CHAINING_OPPORTUNITIES", "")

        chains = []
        for line in chain_section.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                chain_match = re.search(r"with_(\w+):\s*\"(.+?)\"", line)
                if chain_match:
                    chains.append({
                        "with": chain_match.group(1),
                        "payload": chain_match.group(2)
                    })

        return chains

    def get_redirect_types(self):
        open_redirect_learning = self.get_learning_config("open_redirect")
        types_section = open_redirect_learning.get("REDIRECT_TYPES", "")

        types = []
        for line in types_section.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                types.append(line[1:].strip())

        return types

    def get_operation_types(self):
        race_learning = self.get_learning_config("race_conditions")
        types_section = race_learning.get("OPERATION_TYPES", "")

        types = []
        for line in types_section.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                types.append(line[1:].strip())

        return types

    def get_redirect_status_codes(self):
        open_redirect_decision = self.get_decision_rules("open_redirect")
        codes_section = open_redirect_decision.get("REDIRECT_STATUS_CODES", "")

        codes = {}
        for line in codes_section.split("\n"):
            line = line.strip()
            if line.startswith("-"):
                code_match = re.search(r"(\d+):\s*(.+)", line)
                if code_match:
                    codes[int(code_match.group(1))] = code_match.group(2).strip()

        return codes

    def get_file_targets(self, vuln_type):
        advanced = self.get_advanced_config(vuln_type)
        targets = {}

        for section_name, content in advanced.items():
            if "TARGET" in section_name and "FILES" in section_name:
                for line in content.split("\n"):
                    line = line.strip()
                    if line.startswith("-"):
                        file_match = re.search(r"\"(.+?)\"(?:\s*\((.+?)\))?", line)
                        if file_match:
                            filepath = file_match.group(1)
                            description = file_match.group(2) if file_match.group(2) else ""
                            if section_name not in targets:
                                targets[section_name] = []
                            targets[section_name].append({
                                "path": filepath,
                                "description": description
                            })

        return targets

    def get_no_sql_payloads(self):
        sqli_advanced = self.get_advanced_config("sqli")
        payloads = []

        mongodb_section = sqli_advanced.get("MONGODB OPERATOR PAYLOADS", "")
        couchdb_section = sqli_advanced.get("COUCHDB NOSQL INJECTION", "")

        for section in [mongodb_section, couchdb_section]:
            login_matches = re.findall(r"login:\s*(\{.+?\})", section)
            query_matches = re.findall(r"query:\s*(\{.+?\})", section)
            param_matches = re.findall(r"param:\s*(\{.+?\})", section)
            payload_matches = re.findall(r"payload:\s*(\{.+?\})", section)
            field_matches = re.findall(r"field:\s*(\{.+?\})", section)

            for match in login_matches + query_matches + param_matches + payload_matches + field_matches:
                payloads.append(match)

        safe_section = sqli_advanced.get("SAFE TEST PAYLOADS FOR NOSQL", "")
        safe_matches = re.findall(r"value:\s*'(\{.+?\})'", safe_section)
        for match in safe_matches:
            payloads.append(match)

        return payloads

    def get_ldap_payloads(self):
        sqli_advanced = self.get_advanced_config("sqli")
        payloads = []

        ldap_section = sqli_advanced.get("LDAP INJECTION PAYLOADS", "")
        username_matches = re.findall(r"username:\s*(.+?)\n", ldap_section)
        password_matches = re.findall(r"password:\s*(.+?)\n", ldap_section)
        payload_matches = re.findall(r"payload:\s*\"(.+?)\"", ldap_section)

        for match in username_matches + password_matches + payload_matches:
            payloads.append(match.strip())

        safe_section = sqli_advanced.get("SAFE TEST PAYLOADS FOR LDAP", "")
        safe_matches = re.findall(r"value:\s*\"(.+?)\"", safe_section)
        for match in safe_matches:
            payloads.append(match)

        return payloads

    def get_soap_xxe_payloads(self):
        xxe_advanced = self.get_advanced_config("xxe")
        payloads = []

        for section_name, content in xxe_advanced.items():
            if "SOAP" in section_name:
                payload_matches = re.findall(r"payload:\s*\|((?:\n.*)+?)(?=\n\s{0,3}\[|\n\s{0,3}max_|\n\s{2}type:)", content, re.DOTALL)
                for match in payload_matches:
                    payloads.append(match.strip())

        return payloads

    def get_svg_xxe_payloads(self):
        xxe_advanced = self.get_advanced_config("xxe")
        payloads = []

        for section_name, content in xxe_advanced.items():
            if "SVG" in section_name:
                payload_matches = re.findall(r"payload:\s*\|((?:\n.*)+?)(?=\n\s{0,3}\[|\n\s{0,3}max_)", content, re.DOTALL)
                for match in payload_matches:
                    payloads.append(match.strip())

        return payloads

    def get_ssrf_safe_payloads(self):
        ssrf_detection = self.get_detection_config("ssrf")
        payloads = []

        test_method = ssrf_detection.get("TEST_METHOD", "")
        safe_matches = re.findall(r"- name:\s*(.+?)\s*\n\s+value:\s*\"(.+?)\"", test_method)
        for name, value in safe_matches:
            payloads.append({"name": name.strip(), "value": value})

        return payloads

    def get_xss_safe_payloads(self):
        xss_detection = self.get_detection_config("xss")
        payloads = []

        KNOWN_SINGLE_CHAR_PAYLOADS = {
            'single_quote': "'",
            'double_quote': '"',
            'backtick': '`',
        }

        test_method = xss_detection.get("TEST_METHOD", "")
        safe_matches = re.findall(r"- name:\s*(.+?)\s*\n\s+value:\s*[\"'](.+?)[\"']", test_method)
        for name, value in safe_matches:
            payloads.append({"name": name.strip(), "value": value})

        for p in payloads:
            if not p.get('value', '').strip() and p.get('name') in KNOWN_SINGLE_CHAR_PAYLOADS:
                p['value'] = KNOWN_SINGLE_CHAR_PAYLOADS[p['name']]
                p['_is_valid'] = True

        return payloads

    def get_sqli_safe_payloads(self):
        sqli_detection = self.get_detection_config("sqli")
        payloads = []

        KNOWN_SINGLE_CHAR_PAYLOADS = {
            'single_quote': "'",
            'double_quote': '"',
            'backtick': '`',
        }

        test_method = sqli_detection.get("TEST_METHOD", "")
        safe_matches = re.findall(r"- name:\s*(.+?)\s*\n\s+value:\s*[\"'](.+?)[\"']", test_method)
        for name, value in safe_matches:
            payloads.append({"name": name.strip(), "value": value})

        for p in payloads:
            if not p.get('value', '').strip() and p.get('name') in KNOWN_SINGLE_CHAR_PAYLOADS:
                p['value'] = KNOWN_SINGLE_CHAR_PAYLOADS[p['name']]
                p['_is_valid'] = True

        return payloads

    def get_path_traversal_safe_payloads(self, os_type="linux"):
        pt_detection = self.get_detection_config("path_traversal")
        payloads = []

        test_method = pt_detection.get("TEST_METHOD", "")
        os_section = re.search(rf"{os_type}:\s*\n((?:\s+- name:.*\n\s+value:.*\n?)+)", test_method)
        if os_section:
            safe_matches = re.findall(r"- name:\s*(.+?)\s*\n\s+value:\s*[\"'](.+?)[\"']", os_section.group(1))
            for name, value in safe_matches:
                payloads.append({"name": name.strip(), "value": value})

        return payloads

    def get_blind_xxe_payloads(self):
        xxe_advanced = self.get_advanced_config("xxe")
        payloads = []

        for section_name, content in xxe_advanced.items():
            if "BLIND" in section_name:
                payload_matches = re.findall(r"payload:\s*\|((?:\n.*)+?)(?=\n\s{0,3}\[|\n\s{0,3}dtd_content|\n\s{0,3}max_)", content, re.DOTALL)
                for match in payload_matches:
                    payloads.append(match.strip())

                dtd_matches = re.findall(r"dtd_content:\s*\|((?:\n.*)+?)(?=\n\s{0,3}\[|\n\s{0,3}max_|\n\s{2}type:)", content, re.DOTALL)
                for match in dtd_matches:
                    payloads.append(match.strip())

        return payloads

    def get_internal_service_targets(self):
        ssrf_advanced = self.get_advanced_config("ssrf")
        services = []

        for section_name, content in ssrf_advanced.items():
            if "INTERNAL" in section_name:
                type_matches = re.findall(r"- type:\s*(.+?)\s*\n\s+payload:\s*[\"'](.+?)[\"']", content)
                for svc_type, payload in type_matches:
                    services.append({"type": svc_type.strip(), "payload": payload})

        return services

    def get_summary(self):
        return {
            "total_files_loaded": sum(1 for m in self.modules.values() for _ in m["categories"]),
            "vuln_types": sorted(list(self.vuln_types)),
            "modules": list(self.modules.keys()),
            "decision_rules_count": sum(len(r) for r in self.decision_rules.values()),
            "detection_configs": len(self.detection_patterns),
            "advanced_configs": len(self.advanced_configs),
            "learning_configs": len(self.learning_configs)
        }
