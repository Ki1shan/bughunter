import json
import httpx
import asyncio
from modules.logging_config import logger
from modules.rag_loader import RAGLoader
from modules.rag_integration import RAGIntegration


class AIEngine:
    def __init__(self, config, rag_integration=None):
        self.config = config
        self.lm_studio_url = config.get("lm_studio_url", "http://localhost:1234/v1/chat/completions")
        self.model_name = config.get("model_name", "llama-3-8b")
        self.ai_enabled = config.get("ai_enabled", True)
        self.timeout = 60
        self.rag = rag_integration
        if not self.rag:
            self.rag = RAGIntegration(config)

    async def chat(self, system_prompt, user_message):
        if not self.ai_enabled:
            return {"error": "AI disabled in config", "response": None}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "model": self.model_name,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 2000
                }

                response = await client.post(self.lm_studio_url, json=payload)

                if response.status_code == 200:
                    result = response.json()
                    return {
                        "response": result["choices"][0]["message"]["content"],
                        "model": result.get("model", self.model_name),
                        "usage": result.get("usage", {})
                    }
                else:
                    logger.error(f"AI API error: {response.status_code} - {response.text}")
                    return {"error": f"API error: {response.status_code}", "response": None}

        except httpx.ConnectError:
            logger.error("Cannot connect to LM Studio - is it running?")
            return {"error": "Connection to LM Studio failed", "response": None}
        except Exception as e:
            logger.error(f"AI request error: {e}")
            return {"error": str(e), "response": None}

    def build_system_prompt(self, rag_context=None):
        prompt = """You are an expert penetration tester and security researcher.
Analyze endpoint data, vulnerability findings, and anomalies.
Suggest specific vulnerabilities, precise attack steps, working payloads, and chaining opportunities.
Be practical and actionable. Focus on confirmed issues first, then theoretical risks.
Format responses as structured analysis with clear recommendations."""
        
        if rag_context:
            prompt += f"\n\nRAG KNOWLEDGE BASE:\n{rag_context}"
        
        return prompt

    def build_analysis_prompt(self, endpoint, logic_findings, heuristic_findings, score_results, chain_results):
        prompt = f"""Analyze this endpoint for vulnerabilities:

ENDPOINT: {endpoint['url']}
METHOD: {endpoint.get('method', 'GET')}
PARAMETERS: {', '.join(endpoint.get('params', []))}

LOGIC FINDINGS (rule-based detection):
{json.dumps(logic_findings, indent=2) if logic_findings else "None"}

HEURISTIC FINDINGS (anomaly detection):
{json.dumps(heuristic_findings, indent=2) if heuristic_findings else "None"}

SCORE: {score_results.get('score', 0)} ({score_results.get('severity', 'unknown')})
CONFIDENCE: {score_results.get('confidence', 'unknown')}

VULNERABILITY CHAINS:
{json.dumps(chain_results.get('chains', []), indent=2) if chain_results.get('chains') else "None"}

Based on this data:
1. What vulnerabilities are most likely?
2. What specific payloads would you recommend testing?
3. What additional tests would confirm or rule out each finding?
4. Are there any chaining opportunities not already identified?

Provide practical, actionable recommendations."""

        return prompt

    async def analyze_endpoint(self, endpoint, logic_findings, heuristic_findings, score_results, chain_results):
        vuln_types = list(set(f.get("type", "") for f in logic_findings if f.get("type")))
        rag_context = self.rag.get_rag_context_for_ai(vuln_types, endpoint)
        
        system_prompt = self.build_system_prompt(rag_context)
        user_prompt = self.build_analysis_prompt(endpoint, logic_findings, heuristic_findings, score_results, chain_results)

        result = await self.chat(system_prompt, user_prompt)

        return {
            "ai_analysis": result.get("response"),
            "ai_error": result.get("error"),
            "model_used": result.get("model"),
            "tokens_used": result.get("usage", {}).get("total_tokens", 0),
            "rag_context_used": rag_context is not None
        }

    async def suggest_attacks(self, endpoint, findings, knowledge_base):
        vuln_types = [f.get("type") for f in findings]
        
        tests_to_run = []
        for vtype in vuln_types:
            if vtype in knowledge_base:
                tests_to_run.extend(knowledge_base[vtype].get("tests", []))

        prompt = f"""For endpoint {endpoint['url']}, generate specific attack payloads for vulnerabilities: {', '.join(vuln_types)}

Knowledge base tests:
{json.dumps(tests_to_run, indent=2)}

Generate a JSON array of attack objects with:
- description: what the test does
- payload: the actual payload to send
- expected: what indicates success
- severity: low/medium/high/critical"""

        result = await self.chat(self.build_system_prompt(), prompt)

        try:
            if result.get("response"):
                attacks = json.loads(result["response"])
                return attacks
        except json.JSONDecodeError:
            pass

        return []

    async def feedback_loop(self, endpoint, initial_analysis, test_results, iteration=1):
        if iteration > 3:
            return initial_analysis

        prompt = f"""Previous analysis for {endpoint['url']}:
{initial_analysis.get('ai_analysis', '')}

Test results executed:
{json.dumps(test_results, indent=2)}

Based on these test results:
1. Which vulnerabilities were confirmed?
2. Which were false positives?
3. What new attack vectors should be explored?

Update your analysis:"""

        result = await self.chat(self.build_system_prompt(), prompt)
        
        return {
            "ai_analysis": result.get("response"),
            "ai_error": result.get("error"),
            "iteration": iteration,
            "feedback_count": iteration
        }


async def run_ai_analysis(config, endpoint, logic_findings, heuristic_findings, score_results, chain_results, rag_integration=None):
    engine = AIEngine(config, rag_integration)
    return await engine.analyze_endpoint(endpoint, logic_findings, heuristic_findings, score_results, chain_results)