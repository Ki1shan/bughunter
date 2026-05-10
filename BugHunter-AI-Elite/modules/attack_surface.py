import asyncio
import json
import re
from urllib.parse import urljoin, urlparse
from modules.logging_config import logger
from modules.execution_controller import get_execution_controller, ExecutionController


class AttackSurfaceExpander:
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
    
    async def init_session(self, headers=None):
        return None
    
    async def _safe_get(self, session, url, **kwargs):
        metadata = {"module": "attack_surface", "vuln_type": "recon"}
        
        try:
            if self.exec_controller:
                response = await self.exec_controller.get(url, allow_redirects=True, metadata=metadata)
                
                if response and not response.error:
                    return MockResponse(response.status_code, response.body, response.headers)
            
            fallback = ExecutionController(self.config)
            response = await fallback.get(url, allow_redirects=True, metadata=metadata)
            await fallback.close()
            
            if response and not response.error:
                return MockResponse(response.status_code, response.body, response.headers)
            
            return None
            
        except Exception as e:
            logger.debug(f"Error for {url}: {e}")
            return None
    
    async def _safe_request(self, session, method, url, **kwargs):
        return await self._safe_get(session, url, **kwargs)
    
    async def expand_subdomains(self, domain):
        subdomains = []
        
        common_prefixes = [
            "www", "api", "admin", "dev", "test", "staging", "beta", "v2",
            "app", "mobile", "web", "mail", "ftp", "cdn", "static",
            "dashboard", "portal", "client", "server", "login", "auth",
            "secure", "shop", "store", "blog", "forum", "docs", "help",
            "status", "monitor", "metrics", "grafana", "prometheus",
            "jenkins", "gitlab", "github", "jira", "confluence",
            "vpn", "proxy", "gateway", "lb", "loadbalancer"
        ]
        
        common_suffixes = [
            "-dev", "-test", "-staging", "-prod", "-production",
            "-v2", "-v3", "-old", "-new", "-backup", "-legacy"
        ]
        
        target_domain = domain.replace("www.", "")
        
        for prefix in common_prefixes:
            subdomains.append(f"{prefix}.{target_domain}")
        
        for prefix in common_prefixes:
            for suffix in common_suffixes:
                subdomains.append(f"{prefix}{suffix}.{target_domain}")
        
        return list(set(subdomains[:100]))
    
    async def check_subdomain_live(self, subdomain, scheme="https"):
        url = f"{scheme}://{subdomain}/"
        
        try:
            session = await self.init_session()
            response = await self._safe_get(session, url, follow_redirects=True)
            await session.aclose()
            
            if response and response.status_code < 500:
                return {
                    "subdomain": subdomain,
                    "status": response.status_code,
                    "live": True,
                    "redirects_to": str(response.url) if response.url != url else None
                }
        except:
            try:
                session = await self.init_session()
                response = await self._safe_get(session, f"http://{subdomain}/")
                await session.aclose()
                
                if response and response.status_code < 500:
                    return {
                        "subdomain": subdomain,
                        "status": response.status_code,
                        "live": True,
                        "redirects_to": str(response.url)
                    }
            except:
                pass
        
        return {"subdomain": subdomain, "live": False}
    
    async def fuzz_api_endpoints(self, base_url):
        discovered = []
        
        common_api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3", "/api/v1.0",
            "/api/users", "/api/user", "/api/auth", "/api/login",
            "/api/admin", "/api/test", "/api/dev", "/api/debug",
            "/api/keys", "/api/token", "/api/session",
            "/api/users/1", "/api/user/profile", "/api/user/settings",
            "/api/posts", "/api/post", "/api/comments",
            "/api/products", "/api/orders", "/api/transactions",
            "/api/search", "/api/query", "/api/filter",
            "/graphql", "/graphql/v1", "/graphiql",
            "/rest", "/rest/api", "/rest/v1",
            "/swagger", "/swagger.json", "/swagger-ui", "/api-docs",
            "/openapi.json", "/api.yaml", "/api.yml",
            "/wp-json", "/wp-admin", "/xmlrpc.php",
            "/actuator", "/actuator/health", "/actuator/info",
            "/robots.txt", "/sitemap.xml"
        ]
        
        session = await self.init_session()
        semaphore = asyncio.Semaphore(20)
        
        async def check_path(path):
            url = urljoin(base_url, path)
            async with semaphore:
                response = await self._safe_get(session, url)
                if response and response.status_code < 500:
                    result = {
                        "url": url,
                        "method": "GET",
                        "status": response.status_code,
                        "length": len(response.content),
                        "has_json": "application/json" in response.headers.get("content-type", "")
                    }
                    
                    if response.status_code == 405:
                        post_response = await self._safe_request(session, "POST", url)
                        if post_response and post_response.status_code < 500:
                            return [result, {
                                "url": url,
                                "method": "POST",
                                "status": post_response.status_code,
                                "length": len(post_response.content)
                            }]
                    return [result]
                return []
        
        tasks = [check_path(path) for path in common_api_paths]
        results = await asyncio.gather(*tasks)
        
        for result_list in results:
            discovered.extend(result_list)
        
        await session.aclose()
        
        return discovered
    
    async def discover_hidden_routes(self, base_url, known_routes=None):
        discovered = []
        
        hidden_route_patterns = [
            "admin", "api", "auth", "login", "user", "profile",
            "debug", "test", "config", "settings", "backup", "upload"
        ]
        
        route_suffixes = ["", "/", "/index", "/list", "/view"]
        
        session = await self.init_session()
        semaphore = asyncio.Semaphore(20)
        
        async def check_route(pattern, suffix):
            route = f"/{pattern}{suffix}"
            results = []
            for method in ["GET", "HEAD", "OPTIONS"][:3]:
                url = urljoin(base_url, route)
                async with semaphore:
                    response = await self._safe_request(session, method, url)
                    if response and response.status_code < 500 and response.status_code != 404:
                        if response.status_code != 301 or response.headers.get("location"):
                            results.append({
                                "url": url,
                                "method": method,
                                "status": response.status_code,
                                "discovered_via": "route_fuzz"
                            })
            return results
        
        tasks = [check_route(pattern, suffix) for pattern in hidden_route_patterns for suffix in route_suffixes]
        results = await asyncio.gather(*tasks)
        
        for result_list in results:
            discovered.extend(result_list)
        
        await session.aclose()
        
        return discovered
    
    async def parameter_fuzzing(self, endpoint_url):
        discovered = []
        
        common_params = [
            "id", "user_id", "uid", "uuid", "account_id", "order_id",
            "page", "limit", "offset", "sort", "order", "dir", "filter",
            "search", "q", "query", "term", "keyword",
            "action", "cmd", "execute", "run", "func", "function",
            "data", "payload", "input", "request", "redirect", "return",
            "file", "path", "filename", "template", "view", "mode",
            "token", "key", "auth", "secret", "debug", "verbose",
            "callback", "jsonp", "embed", "src", "source", "dest"
        ]
        
        session = await self.init_session()
        semaphore = asyncio.Semaphore(10)
        
        baseline = await self._safe_get(session, endpoint_url)
        if not baseline:
            await session.aclose()
            return discovered
        
        async def check_param(param):
            async with semaphore:
                response = await self._safe_get(session, endpoint_url, params={param: "test"})
                if response and response.status_code != baseline.status_code:
                    return {
                        "url": endpoint_url,
                        "sensitive_param": param,
                        "status_change": response.status_code,
                        "baseline_status": baseline.status_code,
                        "type": "sensitive_param_discovery"
                    }
            return None
        
        tasks = [check_param(param) for param in common_params[:20]]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                discovered.append(result)
        
        await session.aclose()
        
        return discovered
    
    async def expand_all(self, target_url):
        target_domain = urlparse(target_url).netloc
        
        logger.info(f"[Attack Surface] Expanding for {target_domain}")
        
        all_results = {
            "subdomains": [],
            "api_endpoints": [],
            "hidden_routes": [],
            "sensitive_params": []
        }
        
        if "127.0.0.1" in target_url or "localhost" in target_url:
            logger.info("[Attack Surface] Skipping expansion for localhost target")
            all_results["sensitive_params"] = await self.parameter_fuzzing(target_url)
            return all_results
        
        if self.config.get("subdomain_enum", True):
            logger.info("[Attack Surface] Fuzzing subdomains...")
            subdomains = await self.expand_subdomains(target_domain)
            logger.info(f"[Attack Surface] Testing {len(subdomains)} subdomains...")
            
            for subdomain in subdomains[:20]:
                result = await self.check_subdomain_live(subdomain)
                if result.get("live"):
                    all_results["subdomains"].append(result)
                    logger.info(f"  [+] Found live subdomain: {subdomain}")
        
        if self.config.get("api_fuzzing", True):
            logger.info("[Attack Surface] Fuzzing API endpoints...")
            api_results = await self.fuzz_api_endpoints(target_url)
            all_results["api_endpoints"] = api_results
            logger.info(f"  [+] Found {len(api_results)} API endpoints")
        
        if self.config.get("hidden_route_discovery", True):
            logger.info("[Attack Surface] Discovering hidden routes...")
            hidden = await self.discover_hidden_routes(target_url)
            all_results["hidden_routes"] = hidden
            logger.info(f"  [+] Found {len(hidden)} hidden routes")
        
        logger.info("[Attack Surface] Parameter fuzzing...")
        params = await self.parameter_fuzzing(target_url)
        all_results["sensitive_params"] = params
        
        return all_results


async def expand_attack_surface(config, target_url):
    expander = AttackSurfaceExpander(config)
    return await expander.expand_all(target_url)