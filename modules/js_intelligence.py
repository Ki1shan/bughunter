import re
import json
from urllib.parse import urljoin, urlparse
from modules.logging_config import logger
from modules.execution_controller import get_execution_controller, ExecutionResponse


class JSIntelligenceEngine:
    def __init__(self, config):
        self.config = config
        self.user_agent = config.get("user_agent", "BugHunter-AI/v1.0")
        self.timeout = config.get("request_timeout", 10)
        self._exec_controller = None
        self._use_controller = True
    
    @property
    def exec_controller(self):
        if self._exec_controller is None and self._use_controller:
            try:
                self._exec_controller = get_execution_controller(self.config)
            except Exception:
                self._use_controller = False
        return self._exec_controller
        
    async def fetch_js_files(self, html, base_url):
        js_files = []
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
        
        matches = script_pattern.findall(html)
        for match in matches:
            js_url = urljoin(base_url, match)
            if js_url not in js_files:
                js_files.append(js_url)
        
        inline_pattern = re.compile(r'<script[^>]*>([^<]+)</script>', re.I)
        inline_scripts = inline_pattern.findall(html)
        
        return js_files, inline_scripts
    
    async def fetch_js_content(self, js_url):
        metadata = {"module": "js_intelligence", "vuln_type": "recon"}
        
        try:
            if self.exec_controller:
                response = await self.exec_controller.get(js_url, headers={"User-Agent": self.user_agent}, metadata=metadata)
                if response and response.status_code == 200:
                    return response.body
            
            from modules.execution_controller import ExecutionController
            fallback = ExecutionController(self.config)
            fallback.timeout = self.timeout
            response = await fallback.get(js_url, headers={"User-Agent": self.user_agent}, metadata=metadata)
            await fallback.close()
            
            if response and response.status_code == 200:
                return response.body
            
            return None
            
        except Exception as e:
            logger.error(f"JS fetch error ({js_url}): {e}")
        return None
    
    def extract_endpoints(self, js_content):
        endpoints = []
        
        api_patterns = [
            r'"([^"]+/api/[^"]+)"',
            r"'(.+?/api/[^']+)'",
            r'(?:http[s]?://[^/]+)?(/api/[^\s"\'<>]+)',
            r'endpoint\s*:\s*["\']([^"\']+)["\']',
            r'path\s*:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.I)
            endpoints.extend(matches)
        
        return list(set(endpoints))
    
    def extract_parameters(self, js_content):
        params = set()
        
        param_patterns = [
            r'(?:query|param|filter|search|term)\s*:\s*["\']([^"\']+)["\']',
            r'(?:GET|POST|PUT|DELETE)\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in param_patterns:
            matches = re.findall(pattern, js_content, re.I)
            for match in matches:
                if "?" in match:
                    param_part = match.split("?")[1]
                    for param in param_part.split("&"):
                        if "=" in param:
                            params.add(param.split("=")[0])
        
        return list(params)
    
    def extract_tokens(self, js_content):
        tokens = []
        
        token_patterns = [
            (r'token["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', "token"),
            (r'apiKey["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', "apiKey"),
            (r'api_key["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', "api_key"),
            (r'Authorization["\']?\s*[:=]\s*["\']([^"\']{10,})["\']', "Authorization"),
            (r'Bearer\s+([a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)', "JWT"),
        ]
        
        for pattern, token_type in token_patterns:
            matches = re.findall(pattern, js_content, re.I)
            for match in matches:
                tokens.append({"type": token_type, "value": match[:20] + "..."})
        
        return tokens
    
    def extract_hidden_routes(self, js_content):
        routes = []
        
        route_patterns = [
            r'(?:router|route|Navigate)\.push\s*\(\s*["\']([^"\']+)["\']',
            r'(?:router|route|Navigate)\.*go\s*\(\s*["\']([^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in route_patterns:
            matches = re.findall(pattern, js_content, re.I)
            routes.extend(matches)
        
        admin_routes = re.findall(r'(?:admin|dashboard|manage|settings|config|debug)[^\s"\'<>]*', js_content, re.I)
        routes.extend(admin_routes)
        
        return list(set(routes))
    
    def extract_api_versions(self, js_content):
        versions = re.findall(r'/api/v(\d+)/', js_content, re.I)
        return list(set(versions))
    
    async def analyze_html(self, html, base_url):
        results = {
            "js_files": [],
            "endpoints": [],
            "parameters": [],
            "tokens_found": [],
            "hidden_routes": [],
            "api_versions": []
        }
        
        js_files, inline_scripts = await self.fetch_js_files(html, base_url)
        results["js_files"] = js_files
        
        for js_url in js_files:
            js_content = await self.fetch_js_content(js_url)
            if js_content:
                results["endpoints"].extend(self.extract_endpoints(js_content))
                results["parameters"].extend(self.extract_parameters(js_content))
                results["tokens_found"].extend(self.extract_tokens(js_content))
                results["hidden_routes"].extend(self.extract_hidden_routes(js_content))
                results["api_versions"].extend(self.extract_api_versions(js_content))
        
        for inline in inline_scripts:
            results["endpoints"].extend(self.extract_endpoints(inline))
            results["parameters"].extend(self.extract_parameters(inline))
            results["hidden_routes"].extend(self.extract_hidden_routes(inline))
        
        for key in results:
            results[key] = list(set(results[key]))
        
        logger.info(f"JS Analysis: {len(results['endpoints'])} endpoints, {len(results['tokens_found'])} tokens found")
        
        return results


async def run_js_analysis(config, html, base_url):
    engine = JSIntelligenceEngine(config)
    return await engine.analyze_html(html, base_url)