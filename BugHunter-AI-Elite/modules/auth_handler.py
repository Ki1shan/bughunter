import json
import httpx
from modules.logging_config import logger


class AuthHandler:
    def __init__(self, config):
        self.config = config
        self.session = None
        self.auth_tokens = {}
        self.user_agent = config.get("user_agent", "BugHunter-AI/v1.0")
        self.timeout = config.get("request_timeout", 10)
        
    async def init_session(self):
        self.session = httpx.AsyncClient(
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            follow_redirects=True
        )
        
    async def close(self):
        if self.session:
            await self.session.aclose()
            
    async def login(self, login_url, username_field, password_field, credentials):
        await self.init_session()
        
        try:
            response = await self.session.get(login_url)
            
            data = {
                username_field: credentials.get("username", ""),
                password_field: credentials.get("password", "")
            }
            
            login_response = await self.session.post(login_url, data=data)
            
            cookies = dict(self.session.cookies)
            
            self.auth_tokens = {
                "cookies": cookies,
                "logged_in": True
            }
            
            await self.close()
            return self.auth_tokens
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            await self.close()
            return {"logged_in": False, "error": str(e)}
    
    def set_token(self, token_type, token_value):
        self.auth_tokens[token_type] = token_value
        
    def get_auth_headers(self):
        headers = {}
        
        if "bearer" in self.auth_tokens:
            headers["Authorization"] = f"Bearer {self.auth_tokens['bearer']}"
        if "api_key" in self.auth_tokens:
            headers["X-API-Key"] = self.auth_tokens["api_key"]
            
        return headers
    
    async def make_authenticated_request(self, url, method="GET", **kwargs):
        if not self.session:
            await self.init_session()
            
        headers = self.get_auth_headers()
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))
            
        kwargs["headers"] = headers
            
        try:
            response = await getattr(self.session, method.lower())(url, **kwargs)
            return {
                "status_code": response.status_code,
                "cookies": dict(self.session.cookies),
                "text": response.text,
                "headers": dict(response.headers)
            }
        except Exception as e:
            logger.error(f"Auth request error: {e}")
            return None
    
    def is_authenticated(self):
        return self.auth_tokens.get("logged_in", False) or bool(self.auth_tokens.get("bearer"))


async def run_auth_request(config, url, method, auth_data=None, **kwargs):
    handler = AuthHandler(config)
    
    if auth_data:
        if "bearer" in auth_data:
            handler.set_token("bearer", auth_data["bearer"])
        if "api_key" in auth_data:
            handler.set_token("api_key", auth_data["api_key"])
            
    result = await handler.make_authenticated_request(url, method, **kwargs)
    await handler.close()
    return result