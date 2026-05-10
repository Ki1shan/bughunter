"""
SSTI Detector - Identifies Server-Side Template Injection vulnerabilities

LEGAL: For authorized security testing ONLY. Detection only - no command execution.
"""

import asyncio
import httpx
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from modules.logging_config import logger


@dataclass
class SSTITestResult:
    url: str
    param: str
    template_engine: Optional[str]
    vulnerable: bool
    technique: str
    evidence: Dict


class SSTIDetector:
    """
    SSTI Detector - Identifies Server-Side Template Injection
    
    Detection method: 
    1. Inject template syntax into parameters
    2. Analyze response for syntax recognition or error messages
    3. Identify specific template engine
    
    Standard detection used by all professional scanners
    
    DETECTION ONLY - No command execution
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get("request_timeout", 15)
        
        # Template engine fingerprints
        self.engine_fingerprints = {
            "jinja2": {
                "identifiers": ["jinja", "jinja2", "tinker"],
                "error_patterns": [
                    "jinja2.exceptions", "TemplateNotFound", "undefined variable"
                ],
                "test_strings": [
                    "{{7*7}}",
                    "{{config}}",
                    "{{request}}"
                ]
            },
            "jtwig": {
                "identifiers": ["jtwig", "org.jtwig"],
                "error_patterns": [
                    "JtwigException", "org.jtwig", "unable to resolve"
                ],
                "test_strings": [
                    "#{7*7}",
                    "#{T(java.lang.Math).PI}"
                ]
            },
            "freemarker": {
                "identifiers": ["freemarker", "org.freemarker"],
                "error_patterns": [
                    "FreeMarkerException", "freemarker.core"
                ],
                "test_strings": [
                    "${7*7}",
                    "${java",
                    "<#assign ex=\"freemarker\"?eval>"
                ]
            },
            "velocity": {
                "identifiers": ["velocity", "org.apache.velocity"],
                "error_patterns": [
                    "VelocityException", "org.apache.velocity"
                ],
                "test_strings": [
                    "${7*7}",
                    "#set($x=1)"
                ]
            },
            "blade": {
                "identifiers": ["blade", "org.blade"],
                "error_patterns": ["BladeException"],
                "test_strings": ["{{7*7}}", "${1+1}"]
            },
            "twig": {
                "identifiers": ["twig", "Twig_Environment", "org.twig"],
                "error_patterns": [
                    "Twig_Error", "org.twig"
                ],
                "test_strings": [
                    "{{7*7}}",
                    "{{_self.env}}"
                ]
            },
            "dot": {
                "identifiers": ["dot", "dotview", "DOTVUE"],
                "error_patterns": ["dotview", "DOTVUE"],
                "test_strings": ["${7*7}", "{{7*7}}"]
            }
        }
        
        # Generic SSTI test payloads
        self.generic_tests = [
            ("{{7*7}}", "jinja2"),
            ("#{7*7}", "jtwig"),
            ("${7*7}", "freemarker/velocity"),
            ("<%= 7*7 %>", "erb"),
            ("${T(java.lang.Math).PI}", "jtwig")
        ]
        
    def identify_engine(self, response_text: str) -> Optional[str]:
        """Identify template engine from response"""
        
        response_lower = response_text.lower()
        
        for engine, fingerprints in self.engine_fingerprints.items():
            # Check error patterns
            for pattern in fingerprints["error_patterns"]:
                if pattern.lower() in response_lower:
                    return engine
            
            # Check for engine identifiers in response
            for identifier in fingerprints["identifiers"]:
                if identifier in response_lower:
                    return engine
        
        return None
    
    async def test_ssti_basic(
        self,
        url: str,
        param: str,
        session: httpx.AsyncClient,
        method: str = "GET"
    ) -> Optional[SSTITestResult]:
        """Test parameter for SSTI"""
        
        results = []
        
        for test_string, expected_engine in self.generic_tests:
            try:
                if method == "GET":
                    response = await session.get(
                        url,
                        params={param: test_string},
                        timeout=self.timeout
                    )
                else:
                    response = await session.post(
                        url,
                        data={param: test_string},
                        timeout=self.timeout
                    )
                
                response_text = response.text
                response_lower = response_text.lower()
                
                # Check for math evaluation (e.g., "49" for {{7*7}})
                if "49" in response_text:
                    results.append(SSTITestResult(
                        url=url,
                        param=param,
                        template_engine=expected_engine,
                        vulnerable=True,
                        technique="math_evaluation",
                        evidence={"matched": test_string, "response_contains": "49"}
                    ))
                
                # Check for error messages indicating template injection
                error_indicators = [
                    "TemplateNotFound", "undefined variable", "jinja2",
                    "freemarker", "velocity", "twig", "cannot be applied"
                ]
                
                for error in error_indicators:
                    if error in response_lower:
                        engine = self.identify_engine(response_text)
                        
                        results.append(SSTITestResult(
                            url=url,
                            param=param,
                            template_engine=engine,
                            vulnerable=True,
                            technique="error_revealed",
                            evidence={"error": error, "test": test_string}
                        ))
                        break
                        
                # Check for template syntax in output
                template_syntax = re.findall(r'\{\{[^}]+\}\}', response_text)
                if template_syntax:
                    results.append(SSTITestResult(
                        url=url,
                        param=param,
                        template_engine=None,
                        vulnerable=True,
                        technique="reflection",
                        evidence={"reflected": template_syntax[0]}
                    ))
                
            except Exception as e:
                logger.debug(f"SSTI test error: {e}")
        
        # Return first positive result
        for result in results:
            if result.vulnerable:
                return result
        
        return None
    
    async def test_ssti_blind(
        self,
        url: str,
        param: str,
        session: httpx.AsyncClient,
        oob_domain: str
    ) -> Optional[SSTITestResult]:
        """Test for blind SSTI using OOB technique"""
        
        # Payload that would trigger DNS callback if SSTI exists
        blind_payloads = [
            f"{{request.application.__class__.__name__[::-1]}}@{oob_domain}",
            f"${{T(java.net.InetAddress).getByName('{oob_domain}')}}"
        ]
        
        for payload in blind_payloads:
            try:
                response = await session.post(
                    url,
                    data={param: payload},
                    timeout=self.timeout
                )
                # Would need OOB server to detect callback
                # Report as potential blind SSTI
                return SSTITestResult(
                    url=url,
                    param=param,
                    template_engine=None,
                    vulnerable=False,
                    technique="blind_oob",
                    evidence={"sent": True, "callback_expected": oob_domain}
                )
            except:
                pass
        
        return None
    
    async def scan_endpoint(
        self,
        url: str,
        params: List[str],
        method: str = "GET"
    ) -> List[Dict]:
        """Comprehensive SSTI scan"""
        
        results = []
        
        async with httpx.AsyncClient() as session:
            for param in params:
                logger.info(f"[SSTI] Testing {param} at {url}")
                
                result = await self.test_ssti_basic(url, param, session, method)
                
                if result:
                    results.append({
                        "url": url,
                        "param": param,
                        "vulnerable": result.vulnerable,
                        "template_engine": result.template_engine,
                        "technique": result.technique,
                        "evidence": result.evidence
                    })
        
        return results
    
    async def identify_from_response(self, response_text: str) -> Optional[str]:
        """Identify template engine from error messages"""
        return self.identify_engine(response_text)


def create_ssti_detector(config: Dict) -> SSTIDetector:
    """Factory function"""
    return SSTIDetector(config)


if __name__ == "__main__":
    async def test():
        detector = create_ssti_detector({})
        
        test_cases = [
            ("{{7*7}}", "jinja2"),
            ("${7*7}", "freemarker"),
            ("<%= 7*7 %>", "erb")
        ]
        
        print("Test payloads generated successfully")
        
    asyncio.run(test())