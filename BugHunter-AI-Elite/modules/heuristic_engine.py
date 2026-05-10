import json
import time
from modules.logging_config import logger
from modules.execution_controller import get_execution_controller, ExecutionController


class HeuristicEngine:
    def __init__(self, config):
        self.config = config
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
        
    async def init_session(self):
        pass
        
    async def close(self):
        if self._exec_controller:
            await self._exec_controller.close()
            self._exec_controller = None
    
    async def send_request(self, url, method="GET", **kwargs):
        headers = kwargs.get("headers", {})
        if "User-Agent" not in headers:
            headers["User-Agent"] = self.user_agent
        kwargs["headers"] = headers
        
        params = kwargs.pop("params", None)
        data = kwargs.pop("data", None)
        
        metadata = {"module": "heuristic_engine", "vuln_type": "heuristic"}
        
        try:
            if self.exec_controller:
                if method == "GET":
                    response = await self.exec_controller.get(url, params=params, headers=headers, metadata=metadata)
                else:
                    response = await self.exec_controller.post(url, data=data, headers=headers, metadata=metadata)
                
                if response and not response.error:
                    return {
                        "status_code": response.status_code,
                        "headers": response.headers,
                        "text": response.body,
                        "length": len(response.body) if response.body else 0,
                        "url": url
                    }
            
            fallback = ExecutionController(self.config)
            
            if method == "GET":
                response = await fallback.get(url, params=params, headers=headers, metadata=metadata)
            else:
                response = await fallback.post(url, data=data, headers=headers, metadata=metadata)
            
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
    
    async def check_status_change(self, endpoint):
        await self.init_session()
        
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        params = endpoint.get("params", [])
        param = params[0] if params else None
        
        anomalies = []
        
        baseline = await self.send_request(url, method)
        if not baseline:
            await self.close()
            return anomalies
            
        headers_to_test = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "192.168.1.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
        ]
        
        for headers in headers_to_test:
            modified = await self.send_request(url, method, headers=headers)
            if modified and modified["status_code"] != baseline["status_code"]:
                anomalies.append({
                    "type": "status_change",
                    "header": list(headers.keys())[0],
                    "baseline_status": baseline["status_code"],
                    "modified_status": modified["status_code"],
                    "confidence": "medium"
                })
        
        if param:
            modified = await self.send_request(url, method, params={param: "invalid"})
            if modified:
                if modified["status_code"] != baseline["status_code"]:
                    anomalies.append({
                        "type": "status_change",
                        "reason": "Invalid param value causes status change",
                        "confidence": "low"
                    })
        
        await self.close()
        return anomalies
    
    async def check_response_diff(self, endpoint):
        await self.init_session()
        
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        
        baseline = await self.send_request(url, method)
        if not baseline:
            await self.close()
            return []
            
        anomalies = []
        
        variations = [
            {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            {"User-Agent": "python-requests/2.28.0"},
            {"Accept": "application/json"},
            {"Accept": "text/html"},
            {"Accept-Language": "en-US,en;q=0.9"},
        ]
        
        for headers in variations:
            modified = await self.send_request(url, method, headers=headers)
            if modified:
                len_diff = abs(baseline["length"] - modified["length"])
                if len_diff > 100:
                    anomalies.append({
                        "type": "response_diff",
                        "header": list(headers.keys())[0],
                        "baseline_length": baseline["length"],
                        "modified_length": modified["length"],
                        "confidence": "low"
                    })
                
                if baseline["text"] != modified["text"]:
                    anomalies.append({
                        "type": "content_diff",
                        "header": list(headers.keys())[0],
                        "confidence": "low"
                    })
        
        await self.close()
        return anomalies
    
    async def check_timing(self, endpoint):
        await self.init_session()
        
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        
        times = []
        
        for _ in range(3):
            start = time.time()
            response = await self.send_request(url, method)
            elapsed = time.time() - start
            if response:
                times.append(elapsed)
        
        await self.close()
        
        if not times:
            return []
            
        avg_time = sum(times) / len(times)
        
        if avg_time > 2.0:
            return [{
                "type": "timing_delay",
                "average_time": avg_time,
                "confidence": "low"
            }]
        
        if max(times) - min(times) > 1.0:
            return [{
                "type": "inconsistent_timing",
                "times": times,
                "confidence": "low"
            }]
        
        return []
    
    async def check_unexpected_content(self, endpoint):
        await self.init_session()
        
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        
        response = await self.send_request(url, method)
        await self.close()
        
        if not response:
            return []
            
        anomalies = []
        
        info_patterns = [
            (r"\.env", "exposed_env_file"),
            (r"\.git", "exposed_git"),
            (r"config", "config_keyword"),
            (r"password", "password_keyword"),
            (r"api-?key", "api_key_keyword"),
            (r"token", "token_keyword"),
            (r"debug", "debug_mode"),
            (r"stack\s*trace", "stack_trace"),
            (r"fatal|error|exception", "error_keyword"),
        ]
        
        import re
        for pattern, label in info_patterns:
            if re.search(pattern, response["text"], re.I):
                anomalies.append({
                    "type": label,
                    "confidence": "low"
                })
        
        return anomalies
    
    async def analyze_endpoint(self, endpoint):
        await self.init_session()
        all_anomalies = []
        
        try:
            all_anomalies.extend(await self.check_status_change(endpoint))
        except Exception as e:
            logger.error(f"Status change check error: {e}")
            
        try:
            all_anomalies.extend(await self.check_response_diff(endpoint))
        except Exception as e:
            logger.error(f"Response diff check error: {e}")
            
        try:
            all_anomalies.extend(await self.check_timing(endpoint))
        except Exception as e:
            logger.error(f"Timing check error: {e}")
            
        try:
            all_anomalies.extend(await self.check_unexpected_content(endpoint))
        except Exception as e:
            logger.error(f"Unexpected content check error: {e}")
        
        await self.close()
        return all_anomalies


async def run_heuristic_engine(config, endpoint):
    engine = HeuristicEngine(config)
    return await engine.analyze_endpoint(endpoint)