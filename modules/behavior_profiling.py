import json
import re
from urllib.parse import urlparse
from modules.logging_config import logger
from modules.payload_loader import get_payload_loader
from modules.execution_controller import get_execution_controller, ExecutionResponse


class BehaviorProfilingEngine:
    def __init__(self, config):
        self.config = config
        self.user_agent = config.get("user_agent", "BugHunter-AI/v1.0")
        self.timeout = config.get("request_timeout", 10)
        self._payload_loader = None
        self._exec_controller = None
        self._use_controller = True
    
    @property
    def payload_loader(self):
        if self._payload_loader is None:
            self._payload_loader = get_payload_loader()
        return self._payload_loader
    
    @property
    def exec_controller(self):
        if self._exec_controller is None and self._use_controller:
            try:
                self._exec_controller = get_execution_controller(self.config)
            except Exception:
                self._use_controller = False
        return self._exec_controller
        
    async def init_session(self):
        pass
        
    async def close(self):
        if self._exec_controller:
            await self._exec_controller.close()
            self._exec_controller = None
            
    async def send_request(self, url, method="GET", params=None, data=None, headers=None):
        req_headers = headers or {}
        if "User-Agent" not in req_headers:
            req_headers["User-Agent"] = self.user_agent
        
        metadata = {"module": "behavior_profiling", "vuln_type": "profiling"}
        
        try:
            if self.exec_controller:
                if method == "GET":
                    response = await self.exec_controller.get(url, params=params, headers=req_headers, metadata=metadata)
                else:
                    response = await self.exec_controller.post(url, data=data, headers=req_headers, metadata=metadata)
                
                if response and not response.error:
                    return {
                        "status_code": response.status_code,
                        "headers": response.headers,
                        "text": response.body,
                        "length": len(response.body) if response.body else 0,
                        "url": url
                    }
            
            from modules.execution_controller import ExecutionController
            fallback = ExecutionController(self.config)
            fallback.timeout = self.timeout
            
            if method == "GET":
                response = await fallback.get(url, params=params, headers=req_headers, metadata=metadata)
            else:
                response = await fallback.post(url, data=data, headers=req_headers, metadata=metadata)
            
            await fallback.close()
            
            if response and not response.error:
                return {
                    "status_code": response.status_code,
                    "headers": response.headers,
                    "text": response.body,
                    "length": len(response.body) if response.body else 0,
                    "url": url
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None
    
    def compare_responses(self, baseline, modified):
        differences = {}
        
        if baseline["status_code"] != modified["status_code"]:
            differences["status_change"] = {
                "baseline": baseline["status_code"],
                "modified": modified["status_code"]
            }
        
        if abs(baseline["length"] - modified["length"]) > 50:
            differences["length_diff"] = {
                "baseline": baseline["length"],
                "modified": modified["length"],
                "delta": modified["length"] - baseline["length"]
            }
        
        baseline_lower = baseline["text"].lower()
        modified_lower = modified["text"].lower()
        
        if baseline_lower != modified_lower:
            differences["content_diff"] = True
            
            common_words = set(baseline_lower.split()) & set(modified_lower.split())
            all_words = set(baseline_lower.split()) | set(modified_lower.split())
            similarity = len(common_words) / len(all_words) if all_words else 1
            
            differences["similarity"] = similarity
            
        return differences
    
    async def profile_endpoint(self, endpoint):
        await self.init_session()
        
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        params = endpoint.get("params", [])
        
        baseline = await self.send_request(url, method)
        if not baseline:
            return None
            
        profile = {
            "baseline": baseline,
            "tests": []
        }
        
        for param in params:
            test_payloads_raw = [
                "", "test", "1", "999999999", "-1", "0", "null", "undefined",
                "a" * 100, "\t" * 10
            ]
            
            xss_payloads = self.payload_loader.get_payload_values("xss", level="basic", limit=2)
            sqli_payloads = self.payload_loader.get_payload_values("sql-injection", level="basic", limit=2)
            
            test_payloads = test_payloads_raw + xss_payloads + sqli_payloads
            
            for payload in test_payloads:
                test_params = {param: payload}
                
                if method == "GET":
                    modified = await self.send_request(url, method, params=test_params)
                else:
                    modified = await self.send_request(url, method, data=test_params)
                
                if modified:
                    diffs = self.compare_responses(baseline, modified)
                    if diffs:
                        profile["tests"].append({
                            "param": param,
                            "payload": payload,
                            "response": modified["text"],
                            "status": modified["status_code"],
                            "differences": diffs
                        })
        
        await self.close()
        return profile


async def run_behavior_profiling(config, endpoint):
    engine = BehaviorProfilingEngine(config)
    return await engine.profile_endpoint(endpoint)