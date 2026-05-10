"""
Advanced Detection Suite - Unifies all vulnerability detection modules
Integrates: OOB, JWT, Race Condition, SSRF, XXE, SSTI, Deserialization

This module provides a unified interface for all advanced vulnerability detection.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

from modules.oob_callback import create_oob_detector, OOBCallbackDetector
from modules.jwt_detector import create_jwt_detector, JWTDetector
from modules.race_detector import create_race_detector, RaceConditionDetector
from modules.ssrf_detector import create_ssrf_detector, SSRFProbeDetector
from modules.xxe_detector import create_xxe_detector, XXEDetector
from modules.ssti_detector import create_ssti_detector, SSTIDetector
from modules.deser_detector import create_deserialization_detector, DeserializationDetector
from modules.logging_config import logger


class AdvancedDetectionSuite:
    """
    Unified detection suite for advanced vulnerability classes
    
    This is detection only - identifies potential vulnerabilities without exploitation.
    Uses industry-standard detection methodologies (like Burp Collaborator).
    """
    
    def __init__(self, config: Dict):
        self.config = config
        
        # Initialize all detectors
        self.oob_detector: Optional[OOBCallbackDetector] = None
        self.jwt_detector: JWTDetector = create_jwt_detector(config)
        self.race_detector: RaceConditionDetector = create_race_detector(config)
        self.ssrf_detector: SSRFProbeDetector = create_ssrf_detector(config)
        self.xxe_detector: XXEDetector = create_xxe_detector(config)
        self.ssti_detector: SSTIDetector = create_ssti_detector(config)
        self.deser_detector: DeserializationDetector = create_deserialization_detector(config)
        
        self.results = []
        
    async def initialize_oob(self, domain: str = "callback.local"):
        """Initialize OOB callback server"""
        self.oob_detector = create_oob_detector(self.config, domain)
        await self.oob_detector.start_servers()
        logger.info(f"[Detection] OOB server started for {domain}")
    
    async def detect_all(self, endpoint: Dict) -> List[Dict]:
        """
        Run all detection tests on an endpoint
        
        Returns list of findings without exploitation
        """
        findings = []
        url = endpoint.get("url", "")
        params = endpoint.get("params", [])
        method = endpoint.get("method", "GET")
        
        logger.info(f"[Detection] Running advanced detection on {url}")
        
        # JWT Detection (if auth endpoint)
        if any(x in url.lower() for x in ["auth", "login", "token", "jwt", "session"]):
            jwt_results = await self._detect_jwt(url)
            findings.extend(jwt_results)
        
        # SSRF Detection
        ssrf_params = self._find_ssrf_params(params)
        if ssrf_params:
            ssrf_results = await self._detect_ssrf(url, ssrf_params)
            findings.extend(ssrf_results)
        
        # XXE Detection (if XML endpoint)
        if any(x in url.lower() for x in ["xml", "soap", "rss", "feed", "feed"]):
            xxe_results = await self._detect_xxe(url, params)
            findings.extend(xxe_results)
        
        # SSTI Detection (if template endpoint)
        if any(x in url.lower() for x in ["render", "template", "view", "page", "search"]):
            ssti_results = await self._detect_ssti(url, params)
            findings.extend(ssti_results)
        
        # Race Condition Detection
        if method in ["POST", "PUT", "DELETE"]:
            race_results = await self._detect_race_condition(url, method, params)
            findings.extend(race_results)
        
        # Deserialization Detection (if serialized data)
        if any(x in url.lower() for x in ["serialize", "deserialize", "api", "data"]):
            deser_results = await self._detect_insecure_deserialization(url, params)
            findings.extend(deser_results)
        
        return findings
    
    async def _detect_jwt(self, url: str) -> List[Dict]:
        """JWT vulnerability detection"""
        results = []
        
        # Try to get JWT from endpoint
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(url)
                
                # Extract JWT from various headers
                auth_header = response.headers.get("Authorization", "")
                
                if "bearer" in auth_header.lower() or "jwt" in auth_header.lower():
                    token = auth_header.split()[-1]
                    analysis = self.jwt_detector.generate_detection_report(token)
                    
                    if analysis.get("summary", {}).get("total_issues", 0) > 0:
                        results.append({
                            "type": "jwt",
                            "url": url,
                            "vulnerable": True,
                            "severity": analysis["summary"].get("risk_level", "medium"),
                            "findings": analysis.get("vulnerabilities", []),
                            "confidence": "high"
                        })
                        
        except Exception as e:
            logger.debug(f"JWT detection error: {e}")
        
        return results
    
    async def _detect_ssrf(self, url: str, params: List[str]) -> List[Dict]:
        """SSRF vulnerability detection"""
        results = []
        
        try:
            ssrf_results = await self.ssrf_detector.scan_for_ssrf_params(url, params)
            
            for result in ssrf_results:
                if result.get("vulnerable"):
                    results.append({
                        "type": "ssrf",
                        "url": url,
                        "param": result.get("param"),
                        "vulnerable": True,
                        "severity": "high",
                        "confidence": "medium",
                        "evidence": result.get("evidence", {})
                    })
                    
        except Exception as e:
            logger.debug(f"SSRF detection error: {e}")
        
        return results
    
    async def _detect_xxe(self, url: str, params: List[str]) -> List[Dict]:
        """XXE vulnerability detection"""
        results = []
        
        oob_domain = None
        if self.oob_detector:
            oob_domain = self.oob_detector.base_domain
        
        try:
            xxe_results = await self.xxe_detector.scan_endpoint(url, params, oob_domain)
            
            for result in xxe_results:
                if result.get("vulnerable"):
                    results.append({
                        "type": "xxe",
                        "url": url,
                        "param": result.get("param"),
                        "vulnerable": True,
                        "severity": "high",
                        "confidence": "medium",
                        "evidence": result.get("evidence", {})
                    })
                    
        except Exception as e:
            logger.debug(f"XXE detection error: {e}")
        
        return results
    
    async def _detect_ssti(self, url: str, params: List[str]) -> List[Dict]:
        """SSTI vulnerability detection"""
        results = []
        
        try:
            ssti_results = await self.ssti_detector.scan_endpoint(url, params)
            
            for result in ssti_results:
                if result.get("vulnerable"):
                    results.append({
                        "type": "ssti",
                        "url": url,
                        "param": result.get("param"),
                        "vulnerable": True,
                        "severity": "critical",
                        "confidence": "medium",
                        "engine": result.get("template_engine"),
                        "evidence": result.get("evidence", {})
                    })
                    
        except Exception as e:
            logger.debug(f"SSTI detection error: {e}")
        
        return results
    
    async def _detect_race_condition(self, url: str, method: str, params: List[str]) -> List[Dict]:
        """Race condition detection"""
        results = []
        
        try:
            race_result = await self.race_detector.test_endpoint_race(
                url, method, data={} if params else None, concurrent=20
            )
            
            if race_result.potential_vulnerability:
                results.append({
                    "type": "race_condition",
                    "url": url,
                    "method": method,
                    "vulnerable": True,
                    "severity": "medium",
                    "confidence": "medium",
                    "evidence": race_result.details
                })
                
        except Exception as e:
            logger.debug(f"Race detection error: {e}")
        
        return results
    
    async def _detect_insecure_deserialization(self, url: str, params: List[str]) -> List[Dict]:
        """Insecure deserialization detection"""
        results = []
        
        try:
            deser_results = await self.deser_detector.scan_endpoint(url, params)
            
            for result in deser_results:
                if result.get("vulnerable"):
                    results.append({
                        "type": "insecure_deserialization",
                        "url": url,
                        "param": result.get("param"),
                        "format": result.get("format"),
                        "vulnerable": True,
                        "severity": "critical",
                        "confidence": "medium",
                        "evidence": result.get("evidence", {})
                    })
                    
        except Exception as e:
            logger.debug(f"Deserialization detection error: {e}")
        
        return results
    
    def _find_ssrf_params(self, params: List[str]) -> List[str]:
        """Find SSRF-susceptible parameters"""
        ssrf_keywords = ["url", "redirect", "uri", "link", "src", "source", 
                        "domain", "page", "feed", "host", "port", "path", "file"]
        
        return [p for p in params if any(k in p.lower() for k in ssrf_keywords)]
    
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return {
            "oob_active": self.oob_detector is not None,
            "total_findings": len(self.results)
        }


def create_detection_suite(config: Dict) -> AdvancedDetectionSuite:
    """Factory function"""
    return AdvancedDetectionSuite(config)


if __name__ == "__main__":
    async def test():
        suite = create_detection_suite({})
        
        endpoint = {
            "url": "https://example.com/api/fetch",
            "params": ["url", "id"],
            "method": "POST"
        }
        
        # Don't initialize OOB server in test
        results = await suite.detect_all(endpoint)
        
        print(f"Detection results: {results}")
        
    asyncio.run(test())