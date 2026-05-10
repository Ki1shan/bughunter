import asyncio
import json
import httpx
import secrets
from datetime import datetime, timedelta
from modules.logging_config import logger
from modules.execution_controller import get_execution_controller, ExecutionController


DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("user", "user"),
    ("user", "password"),
    ("alice", "alice"),
    ("bob", "bob"),
    ("test", "test"),
    ("guest", "guest"),
    ("charlie", "charlie"),
    ("eve", "eve"),
]

LOGIN_ENDPOINTS = ["/login", "/auth/login", "/api/login", "/signin", "/api/auth/login"]


class MultiUserAuthSimulator:
    def __init__(self, config):
        self.config = config
        self.user_agent = config.get("user_agent", "BugHunter-AI/v1.0")
        self.timeout = config.get("request_timeout", 15)
        self.sessions = {}
        self.users = {}
        self.base_url = ""
        self._discovered_login = None
        self._exec_controller = None
    
    @property
    def exec_controller(self):
        if self._exec_controller is None:
            try:
                self._exec_controller = get_execution_controller(self.config)
            except Exception:
                pass
        return self._exec_controller
    
    async def init_client(self):
        return httpx.AsyncClient(
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
            follow_redirects=True
        )

    async def discover_login_endpoint(self, base_url):
        """Find the login endpoint by testing common paths."""
        if self._discovered_login:
            return self._discovered_login

        self.base_url = base_url.rstrip("/")
        for ep in LOGIN_ENDPOINTS:
            url = f"{self.base_url}{ep}"
            try:
                async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                    resp = await client.get(url)
                    if resp.status_code in (200, 302, 405):
                        self._discovered_login = ep
                        logger.info(f"  [Auth] Discovered login endpoint: {ep}")
                        return ep
            except Exception:
                continue

        logger.info("  [Auth] No login endpoint discovered")
        return None

    async def try_default_credentials(self, base_url):
        """Try default credentials to establish sessions for different roles."""
        login_ep = await self.discover_login_endpoint(base_url)
        if not login_ep:
            return []

        logged_in = []
        for username, password in DEFAULT_CREDENTIALS:
            success = await self.login_with_creds(username, password, base_url, login_ep, session_name=username)
            if success:
                logged_in.append(self.users[username])

        roles_found = set(u["role"] for u in logged_in)
        logger.info(f"  [Auth] Established {len(logged_in)} sessions, roles: {', '.join(roles_found) if roles_found else 'none'}")
        return logged_in

    async def login_with_creds(self, username, password, base_url, login_ep, session_name=None):
        """Attempt login with specific credentials."""
        session_name = session_name or username
        url = f"{base_url.rstrip('/')}{login_ep}"

        try:
            client = await self.init_client()
            resp = await client.post(url, data={"username": username, "password": password})

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    session_id = data.get("session_id")
                    user_data = data.get("user", {})
                except Exception:
                    session_id = None
                    user_data = {}

                profile = {
                    "user_id": user_data.get("id", session_name),
                    "role": user_data.get("role", "user"),
                    "username": username,
                    "created_at": datetime.now().isoformat(),
                    "session": client,
                    "auth_token": session_id,
                    "cookies": dict(client.cookies),
                    "login_successful": True,
                }

                self.users[session_name] = profile
                self.sessions[session_name] = client
                logger.info(f"  [Auth] Logged in as '{username}' (role: {profile['role']})")
                return True
        except Exception as e:
            logger.debug(f"  [Auth] Login error for {username}: {e}")

        return False
    
    async def create_user_profile(self, role="user", user_id=None):
        user_id = user_id or secrets.token_hex(8)
        
        profile = {
            "user_id": user_id,
            "role": role,
            "created_at": datetime.now().isoformat(),
            "session": await self.init_client(),
            "auth_token": secrets.token_urlsafe(32),
            "cookies": {}
        }
        
        self.users[user_id] = profile
        self.sessions[user_id] = profile["session"]
        
        logger.debug(f"Created {role} user: {user_id}")
        return profile
    
    async def simulate_login(self, user_profile, login_url, credentials):
        client = user_profile["session"]
        
        try:
            response = await client.post(login_url, data=credentials)
            
            user_profile["cookies"] = dict(client.cookies)
            user_profile["last_request"] = datetime.now().isoformat()
            user_profile["login_successful"] = response.status_code in [200, 302, 301]
            
            logger.debug(f"Login attempt for {user_profile['user_id']}: {user_profile['login_successful']}")
            return user_profile["login_successful"]
            
        except Exception as e:
            logger.error(f"Login simulation error: {e}")
            return False
    
    async def switch_role(self, user_profile, new_role):
        original_role = user_profile["role"]
        user_profile["role"] = new_role
        user_profile["role_changed_at"] = datetime.now().isoformat()
        
        logger.info(f"Role switch: {original_role} -> {new_role} for user {user_profile['user_id']}")
        return user_profile
    
    async def make_request_as_user(self, user_profile, url, method="GET", **kwargs):
        client = user_profile["session"]
        
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        
        kwargs["headers"]["User-Agent"] = self.user_agent
        
        if user_profile.get("cookies"):
            kwargs["cookies"] = user_profile["cookies"]
        
        if user_profile.get("auth_token"):
            kwargs["headers"]["Authorization"] = f"Bearer {user_profile['auth_token']}"
        
        try:
            if method == "GET":
                response = await client.get(url, **kwargs)
            else:
                response = await client.post(url, **kwargs)
            
            user_profile["last_request"] = datetime.now().isoformat()
            
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "text": response.text,
                "length": len(response.content),
                "cookies_after": dict(client.cookies)
            }
        except Exception as e:
            logger.error(f"User request error: {e}")
            return None
    
    async def test_idor(self, endpoint_url, target_user, victim_user_ids):
        results = []

        for victim_id in victim_user_ids:
            if str(victim_id) == str(target_user["user_id"]):
                continue

            modified_url = endpoint_url
            if "?" in modified_url:
                modified_url = modified_url.split("?")[0]

            params = {"id": str(victim_id)}

            headers = {}
            if target_user.get("auth_token"):
                headers["X-Session-ID"] = target_user["auth_token"]

            victim_response = await self.make_request_as_user(
                target_user, modified_url, "GET", params=params, headers=headers
            )

            if victim_response and victim_response["status_code"] == 200:
                resp_text = victim_response.get("text", "")
                user_id_found = str(victim_id) in resp_text

                results.append({
                    "type": "idor",
                    "victim_id": str(victim_id),
                    "attacker_id": str(target_user["user_id"]),
                    "access_granted": True,
                    "data_leaked": user_id_found,
                    "response_length": victim_response.get("length"),
                    "confidence": "high" if user_id_found else "medium",
                    "reason": f"Accessed victim {victim_id}'s data as {target_user['user_id']}"
                })

        return results
    
    async def test_privilege_escalation(self, endpoint_url, low_privilege_user, high_privilege_actions):
        results = []
        
        for action in high_privilege_actions:
            response = await self.make_request_as_user(
                low_privilege_user, 
                endpoint_url, 
                method=action.get("method", "GET"),
                data=action.get("data"),
                params=action.get("params")
            )
            
            if response and response["status_code"] != 403:
                results.append({
                    "type": "privilege_escalation",
                    "action": action.get("name", "unknown"),
                    "user_role": low_privilege_user["role"],
                    "status_code": response["status_code"],
                    "success": response["status_code"] in [200, 201],
                    "confidence": "high"
                })
        
        return results
    
    async def test_horizontal_privilege_escalation(self, user_a, user_b, target_endpoint):
        results = []
        
        response_a = await self.make_request_as_user(user_a, target_endpoint)
        response_b = await self.make_request_as_user(user_b, target_endpoint)
        
        if response_a and response_b:
            if response_a["status_code"] == 200 and response_b["status_code"] == 200:
                if abs(response_a["length"] - response_b["length"]) > 10:
                    results.append({
                        "type": "horizontal_escalation",
                        "description": "User A can access User B's data",
                        "user_a": user_a["user_id"],
                        "user_b": user_b["user_id"],
                        "response_diff": abs(response_a["length"] - response_b["length"]),
                        "confidence": "medium"
                    })
        
        return results
    
    async def test_vertical_privilege_escalation(self, user, target_role, admin_endpoint):
        results = []
        
        token_manipulation_headers = [
            {"Role": target_role},
            {"X-User-Role": target_role},
            {"X-Admin": "true"},
            {"Authorization": f"Bearer admin_token_{user['user_id']}"}
        ]
        
        for headers in token_manipulation_headers:
            response = await self.make_request_as_user(
                user, admin_endpoint, headers=headers
            )
            
            if response and response["status_code"] in [200, 201]:
                results.append({
                    "type": "vertical_escalation",
                    "technique": "header_manipulation",
                    "header": list(headers.keys())[0],
                    "target_role": target_role,
                    "status_code": response["status_code"],
                    "confidence": "high"
                })
        
        return results
    
    async def test_session_hijacking(self, target_url, users):
        results = []

        if len(users) < 2:
            logger.warning("  [Auth] Session hijacking test requires at least 2 users")
            return results

        victim_session = users[0]["session"]
        attacker_session = users[1]["session"]
        
        victim_cookies = dict(victim_session.cookies)
        
        for cookie_name, cookie_value in victim_cookies.items():
            attacker_session.cookies.set(cookie_name, cookie_value)
        
        response = await attacker_session.get(target_url)
        
        if response.status_code == 200:
            results.append({
                "type": "session_hijacking",
                "description": f"Stolen cookie {list(victim_cookies.keys())} allowed access",
                "confidence": "high"
            })
        
        return results
    
    async def simulate_multi_user_scenario(self, login_url, user_credentials):
        scenarios = []
        
        regular_user = await self.create_user_profile(role="user")
        await self.simulate_login(regular_user, login_url, user_credentials.get("regular", {}))
        
        admin_user = await self.create_user_profile(role="admin")
        await self.simulate_login(admin_user, login_url, user_credentials.get("admin", {}))
        
        scenarios.append({
            "scenario": "regular_vs_admin",
            "users": [regular_user["user_id"], admin_user["user_id"]],
            "roles": [regular_user["role"], admin_user["role"]]
        })
        
        logger.info(f"Created multi-user scenario with {len(scenarios)} scenarios")
        return scenarios
    
    async def cleanup(self):
        for user_id, session in self.sessions.items():
            try:
                await session.aclose()
            except:
                pass
        
        self.sessions.clear()
        self.users.clear()
        
        if self._exec_controller:
            await self._exec_controller.close()
            self._exec_controller = None


async def run_auth_simulation(config, target_url, scenarios=None):
    simulator = MultiUserAuthSimulator(config)
    
    results = {
        "idor_tests": [],
        "privilege_escalation_tests": [],
        "session_tests": []
    }
    
    if scenarios:
        for scenario in scenarios:
            if scenario.get("type") == "idor":
                user_a = await simulator.create_user_profile("user", scenario.get("user_a"))
                results["idor_tests"] = await simulator.test_idor(
                    scenario["endpoint"],
                    user_a,
                    scenario["victim_ids"]
                )
    
    await simulator.cleanup()
    return results