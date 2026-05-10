import json
import httpx
import asyncio
from modules.logging_config import logger


class StrategicAIPlanner:
    def __init__(self, config):
        self.config = config
        self.lm_studio_url = config.get("lm_studio_url", "http://localhost:1234/v1/chat/completions")
        self.model_name = config.get("model_name", "llama-3-8b")
        self.ai_enabled = config.get("ai_enabled", True)
        self.timeout = 90
        
    async def chat(self, system_prompt, user_message):
        if not self.ai_enabled:
            return {"response": None, "error": "AI disabled"}
            
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "model": self.model_name,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    "temperature": 0.4,
                    "max_tokens": 3000
                }
                
                response = await client.post(self.lm_studio_url, json=payload)
                
                if response.status_code == 200:
                    result = response.json()
                    return {
                        "response": result["choices"][0]["message"]["content"],
                        "model": result.get("model", self.model_name)
                    }
                else:
                    return {"error": f"API Error: {response.status_code}"}
                    
        except Exception as e:
            logger.error(f"AI Planner error: {e}")
            return {"error": str(e)}
    
    def build_strategic_prompt(self, all_endpoints, attack_surface_data, previous_findings=None):
        prompt = f"""You are a STRATEGIC PENTEST PLANNER. Your job is to create a COMPREHENSIVE ATTACK PLAN.

CONTEXT:
- Target has {len(all_endpoints)} discovered endpoints
- Attack surface: {len(attack_surface_data.get('subdomains', []))} subdomains, {len(attack_surface_data.get('api_endpoints', []))} API endpoints
- Previous scan found {len(previous_findings) if previous_findings else 0} vulnerabilities

AVAILABLE ENDPOINTS (top priorities):
{json.dumps(all_endpoints[:20], indent=2)}

ATTACK SURFACE SUMMARY:
{json.dumps(attack_surface_data, indent=2)}

YOUR TASK - Create a STRATEGIC attack plan with:
1. PRIMARY TARGETS - Which endpoints to attack first (by priority)
2. ATTACK CHAINS - How to chain vulnerabilities for maximum impact
3. EXPLOITATION STRATEGY - In what order to test each vulnerability class
4. SCOPE EXPANSION - How to find more attack surface
5. CRITICAL PATHS - Which vulnerabilities lead to full compromise

Output as JSON:
{{
    "attack_phases": [
        {{
            "phase": 1,
            "name": "Initial Access",
            "targets": ["endpoint1", "endpoint2"],
            "vulnerabilities_to_test": ["xss", "sql_injection"],
            "priority": "critical",
            "estimated_impact": "description"
        }}
    ],
    "chained_attacks": [
        {{
            "chain_name": "IDOR to Privilege Escalation",
            "steps": ["step1", "step2"],
            "impact": "critical"
        }}
    ],
    "prioritized_endpoints": [],
    "scope_expansion": [],
    "strategic_recommendations": []
}}

Be specific and actionable. Think like an elite penetration tester."""

        return prompt
    
    async def create_attack_plan(self, all_endpoints, attack_surface_data, previous_findings=None):
        prompt = self.build_strategic_prompt(all_endpoints, attack_surface_data, previous_findings)
        
        system = """You are an expert penetration tester and security strategist.
Create detailed, actionable attack plans.
Prioritize by impact and exploitability.
Consider chaining vulnerabilities for maximum damage.
Always think about escalation paths."""

        result = await self.chat(system, prompt)
        
        if result.get("response"):
            try:
                plan = json.loads(result["response"])
                logger.info(f"Strategic plan created with {len(plan.get('attack_phases', []))} phases")
                return plan
            except json.JSONDecodeError:
                return {"raw_plan": result["response"]}
        
        return {"error": result.get("error", "Failed to create plan")}
    
    def build_prioritization_prompt(self, endpoints, knowledge_base):
        prompt = f"""Analyze these {len(endpoints)} endpoints and PRIORITIZE them for testing.

ENDPOINTS:
{json.dumps(endpoints[:30], indent=2)}

Knowledge base priorities:
{json.dumps({k: v.get("severity") for k, v in knowledge_base.items()}, indent=2)}

Return JSON with prioritized list:
{{
    "prioritized": [
        {{"endpoint": "...", "priority_score": 10, "primary_vulns": ["xss", "idor"], "reason": "..."}}
    ],
    "skip": ["endpoint to skip"],
    "reasoning": "..."
}}"""

        return prompt
    
    async def prioritize_endpoints(self, endpoints, knowledge_base):
        prompt = self.build_prioritization_prompt(endpoints, knowledge_base)
        
        system = "You are an attack surface prioritizer. Focus on high-impact, exploitable endpoints."
        
        result = await self.chat(system, prompt)
        
        if result.get("response"):
            try:
                return json.loads(result["response"])
            except json.JSONDecodeError:
                return {"prioritized": endpoints[:10]}
        
        return {"prioritized": endpoints[:10]}
    
    def build_exploitation_prompt(self, vulnerable_endpoint, vuln_type, context):
        prompt = f"""For this VULNERABLE endpoint, create an EXPLOITATION STRATEGY:

ENDPOINT: {vulnerable_endpoint['url']}
VULNERABILITY: {vuln_type}
CONTEXT: {json.dumps(context, indent=2)}

Provide:
1. Exact payloads to use (specific, not generic)
2. Step-by-step exploitation guide
3. Impact assessment 
4. How to escalate this finding for maximum damage

Return JSON:
{{
    "payloads": ["specific_payload_1", "specific_payload_2"],
    "exploitation_steps": ["step1", "step2"],
    "impact": "full database compromise",
    "escalation_path": ["how to escalate"],
    "proof_of_concept": "curl command or Python script"
}}"""

        return prompt
    
    async def plan_exploitation(self, vulnerable_endpoint, vuln_type, context):
        prompt = self.build_exploitation_prompt(vulnerable_endpoint, vuln_type, context)
        
        system = "You are an exploit developer. Create practical, working exploits."
        
        result = await self.chat(system, prompt)
        
        if result.get("response"):
            try:
                return json.loads(result["response"])
            except json.JSONDecodeError:
                return {"raw_exploit_plan": result["response"]}
        
        return {"error": "Failed to plan exploitation"}
    
    def build_recon_prompt(self, tech_stack, previous_scans):
        prompt = f"""Create targeted RECON strategy based on:

TECHNOLOGIES DETECTED: {json.dumps(tech_stack, indent=2)}
PREVIOUS SCANS: {json.dumps(previous_scans, indent=2)}

Suggest:
1. Specific tools and techniques for each technology
2. Known vulnerabilities for the tech stack
3. Custom wordlists needed
4. Configuration to check

Return JSON:
{{
    "recon_techniques": [
        {{"tech": "WordPress", "techniques": ["wpscan", "wpsecrets"]}}
    ],
    "custom_wordlists": ["admin", "api"],
    "known_exploits": [],
    "priority": "high/medium/low"
}}"""

        return prompt
    
    async def plan_recon_strategy(self, tech_stack, previous_scans=None):
        prompt = self.build_recon_prompt(tech_stack, previous_scans or [])
        
        system = "You are a security reconnaissance specialist."
        
        result = await self.chat(system, prompt)
        
        if result.get("response"):
            try:
                return json.loads(result["response"])
            except json.JSONDecodeError:
                return {"recon_techniques": [], "priority": "medium"}
        
        return {"recon_techniques": [], "priority": "medium"}


class AIFeedbackOrchestrator:
    def __init__(self, config):
        self.config = config
        self.planner = StrategicAIPlanner(config)
        
    async def execute_full_cycle(self, scan_data):
        attack_plan = await self.planner.create_attack_plan(
            scan_data.get("endpoints", []),
            scan_data.get("attack_surface", {}),
            scan_data.get("findings", [])
        )
        
        prioritized = await self.planner.prioritize_endpoints(
            scan_data.get("endpoints", []),
            scan_data.get("knowledge_base", {})
        )
        
        return {
            "attack_plan": attack_plan,
            "prioritized": prioritized,
            "ai_powered": True
        }


async def create_strategic_plan(config, endpoints, attack_surface):
    planner = StrategicAIPlanner(config)
    return await planner.create_attack_plan(endpoints, attack_surface)


async def prioritize_targets(config, endpoints, kb):
    planner = StrategicAIPlanner(config)
    return await planner.prioritize_endpoints(endpoints, kb)