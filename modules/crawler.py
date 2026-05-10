import asyncio
import re
import json
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from modules.input_module import parse_url, is_same_domain
from modules.logging_config import logger
from modules.execution_controller import get_execution_controller, ExecutionController


class Crawler:
    def __init__(self, config):
        self.config = config
        self._exec_controller = None
        self.visited = set()
        self.endpoints = []
        self.to_crawl = []
        self.crawl_depth = config.get("crawl_depth", 3)
        self.max_requests = config.get("max_requests", 100)
        self.rate_limit_delay = config.get("rate_limit_delay", 0.5)
        self.user_agent = config.get("user_agent", "BugHunter-AI/v1.0")
        self.timeout = config.get("request_timeout", 10)
        self.base_domain = None
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
            
    async def fetch(self, url, method="GET", data=None, follow_redirects=True):
        await asyncio.sleep(self.rate_limit_delay)
        
        metadata = {"module": "crawler", "vuln_type": "recon"}
        
        try:
            if self.exec_controller:
                if method == "GET":
                    response = await self.exec_controller.get(url, allow_redirects=follow_redirects, metadata=metadata)
                else:
                    response = await self.exec_controller.post(url, data=data, allow_redirects=follow_redirects, metadata=metadata)
                
                if response and not response.error:
                    return {
                        "status_code": response.status_code,
                        "headers": response.headers,
                        "text": response.body,
                        "length": len(response.body) if response.body else 0,
                        "url": response.redirect_url or url
                    }
            
            browser_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
            
            fallback = ExecutionController(self.config)
            
            if method == "GET":
                response = await fallback.get(url, headers=browser_headers, allow_redirects=follow_redirects, metadata=metadata)
            else:
                response = await fallback.post(url, data=data, headers=browser_headers, allow_redirects=follow_redirects, metadata=metadata)
            
            await fallback.close()
            
            if response and not response.error:
                return {
                    "status_code": response.status_code,
                    "headers": response.headers,
                    "text": response.body,
                    "length": len(response.body) if response.body else 0,
                    "url": response.redirect_url or url
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Fetch error ({url}): {type(e).__name__}: {e}")
            return None
            
    def extract_links(self, html, base_url):
        links = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                full_url = urljoin(base_url, href)
                if is_same_domain(full_url, base_url):
                    links.append(full_url)
        except Exception as e:
            logger.error(f"Link extraction error: {e}")
        return list(set(links))
    
    def extract_forms(self, html, base_url):
        forms = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                form_data = {
                    "action": urljoin(base_url, form.get("action", "")),
                    "method": form.get("method", "get").upper(),
                    "inputs": []
                }
                for inp in form.find_all(["input", "textarea", "select"]):
                    input_info = {
                        "name": inp.get("name"),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", "")
                    }
                    form_data["inputs"].append(input_info)
                forms.append(form_data)
        except Exception as e:
            logger.error(f"Form extraction error: {e}")
        return forms
    
    def extract_parameters(self, url):
        params = []
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split("&"):
                if "=" in param:
                    params.append(param.split("=")[0])
        return params
    
    async def discover_endpoints(self, url):
        await self.init_session()
        
        parsed = parse_url(url)
        if not parsed:
            return []
        self.base_domain = parsed["netloc"]
        
        self.to_crawl = [(url, 0)]
        
        while self.to_crawl and len(self.visited) < self.max_requests:
            current_url, depth = self.to_crawl.pop(0)
            
            if current_url in self.visited or depth > self.crawl_depth:
                continue
                
            self.visited.add(current_url)
            
            logger.info(f"Crawling: {current_url} (depth: {depth})")
            
            response = await self.fetch(current_url)
            if not response:
                continue
                
            if response["status_code"] == 200:
                params = self.extract_parameters(current_url)
                
                endpoint = {
                    "url": current_url,
                    "method": "GET",
                    "params": params,
                    "status_code": response["status_code"],
                    "response_length": response["length"],
                    "depth": depth
                }
                self.endpoints.append(endpoint)
                
                forms = self.extract_forms(response["text"], current_url)
                for form in forms:
                    form_endpoint = {
                        "url": form["action"],
                        "method": form["method"],
                        "params": [inp["name"] for inp in form["inputs"] if inp["name"]],
                        "form_inputs": form["inputs"],
                        "source": "form",
                        "depth": depth
                    }
                    self.endpoints.append(form_endpoint)
                
                links = self.extract_links(response["text"], current_url)
                for link in links:
                    if link not in self.visited:
                        self.to_crawl.append((link, depth + 1))
        
        await self.close()
        
        logger.info(f"Crawl complete: {len(self.endpoints)} endpoints found")
        return self.endpoints


async def run_crawler(config, url):
    crawler = Crawler(config)
    endpoints = await crawler.discover_endpoints(url)
    return endpoints