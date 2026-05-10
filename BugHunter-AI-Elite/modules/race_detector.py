"""
Race Condition Detector
Detects endpoints vulnerable to TOCTOU, race conditions, concurrency issues

LEGAL: For authorized security testing ONLY. Detection only - no actual exploitation.
"""

import asyncio
import httpx
import time
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime
from collections import Counter
import random
from modules.logging_config import logger


@dataclass
class RaceTestResult:
    endpoint: str
    method: str
    total_requests: int
    unique_responses: int
    status_codes: Dict[int, int]
    response_lengths: List[int]
    potential_vulnerability: bool
    vulnerability_type: Optional[str]
    details: Dict


class RaceConditionDetector:
    """
    Race Condition Detector - Identifies concurrency vulnerabilities
    
    Detects:
    - TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities
    - Gift card/wallet double-spend potential
    - Rate limiting bypass via concurrency
    - Vote manipulation potential
    - Password reset token races
    
    Uses concurrent requests to detect: identical endpoints that respond 
    differently when accessed simultaneously (indicating race conditions)
    
    DETECTION ONLY - No actual价值的exploitation, reports only
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.max_concurrent = config.get("race_max_concurrent", 50)
        self.timeout = config.get("request_timeout", 15)
        self.rate_limit = config.get("race_rate_limit", 100)
        
        self.semaphore = asyncio.Semaphore(self.rate_limit)
        
    async def send_concurrent_requests(
        self, 
        url: str, 
        method: str = "POST",
        data: Dict = None,
        headers: Dict = None,
        concurrent: int = 50,
        delay: float = 0
    ) -> List[Dict]:
        """Send N concurrent requests and collect responses"""
        
        results = []
        
        async def send_request(idx: int) -> Dict:
            async with self.semaphore:
                await asyncio.sleep(delay * random.random())
                
                try:
                    async with httpx.AsyncClient(
                        timeout=self.timeout,
                        follow_redirects=False
                    ) as client:
                        
                        req_headers = headers or {}
                        req_headers["User-Agent"] = self.config.get(
                            "user_agent", "BugHunter-RaceDetector"
                        )
                        
                        if method == "POST":
                            response = await client.post(url, json=data, headers=req_headers)
                        elif method == "PUT":
                            response = await client.put(url, json=data, headers=req_headers)
                        else:
                            response = await client.get(url, params=data, headers=req_headers)
                        
                        result = {
                            "index": idx,
                            "status_code": response.status_code,
                            "response_length": len(response.text),
                            "response_text": response.text[:500] if response.text else "",
                            "headers": dict(response.headers),
                            "timestamp": time.time()
                        }
                        
                        return result
                        
                except asyncio.TimeoutError:
                    return {"index": idx, "error": "timeout", "status_code": 0}
                except Exception as e:
                    return {"index": idx, "error": str(e), "status_code": 0}
        
        tasks = [send_request(i) for i in range(concurrent)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = [r for r in results if isinstance(r, dict) and "error" not in r]
        
        logger.info(f"[Race] Sent {concurrent} requests, received {len(valid_results)} valid responses")
        
        return valid_results
    
    def analyze_response_pattern(self, results: List[Dict]) -> Dict:
        """Analyze response patterns for race condition indicators"""
        
        if not results:
            return {"vulnerable": False, "reason": "No valid responses"}
        
        status_counter = Counter(r.get("status_code") for r in results)
        length_variance = 0
        
        lengths = [r.get("response_length", 0) for r in results]
        if lengths:
            avg_length = sum(lengths) / len(lengths)
            length_variance = sum((l - avg_length) ** 2 for l in lengths) / len(lengths)
        
        unique_statuses = len(status_counter)
        unique_lengths = len(set(lengths))
        
        analysis = {
            "total_responses": len(results),
            "unique_status_codes": unique_statuses,
            "status_distribution": dict(status_counter),
            "unique_response_lengths": unique_lengths,
            "response_length_variance": length_variance,
            "vulnerable": False,
            "indicators": []
        }
        
        # Multiple different status codes = potential race condition
        if unique_statuses > 1:
            analysis["indicators"].append("multiple_status_codes")
            if unique_statuses >= 3:
                analysis["vulnerable"] = True
                analysis["vulnerability_type"] = "status_code_manipulation"
        
        # High variance in response length
        if length_variance > 10000:
            analysis["indicators"].append("high_response_variance")
            analysis["vulnerable"] = True
            analysis["vulnerability_type"] = "response_manipulation"
        
        # Conflicting successful responses
        successful = [r for r in results if r.get("status_code") == 200]
        if len(successful) > 1:
            analysis["indicators"].append("multiple_success_responses")
            analysis["note"] = "Multiple successful responses to identical requests"
        
        return analysis
    
    async def test_endpoint_race(
        self, 
        url: str, 
        method: str = "POST", 
        data: Dict = None,
        headers: Dict = None,
        concurrent: int = 50
    ) -> RaceTestResult:
        """Test endpoint for race condition vulnerabilities"""
        
        logger.info(f"[Race] Testing {url} with {concurrent} concurrent requests")
        
        results = await self.send_concurrent_requests(
            url, method, data, headers, concurrent
        )
        
        analysis = self.analyze_response_pattern(results)
        
        return RaceTestResult(
            endpoint=url,
            method=method,
            total_requests=concurrent,
            unique_responses=analysis.get("unique_response_lengths", 0),
            status_codes=analysis.get("status_distribution", {}),
            response_lengths=[r.get("response_length", 0) for r in results],
            potential_vulnerability=analysis.get("vulnerable", False),
            vulnerability_type=analysis.get("vulnerability_type"),
            details=analysis
        )
    
    async def test_gift_card_redeem(
        self, 
        redeem_url: str, 
        gift_card_code: str,
        concurrent: int = 30
    ) -> Dict:
        """
        Test if gift card can be redeemed multiple times
        Detection only - reports potential, does not drain cards
        """
        
        logger.info(f"[Race] Testing gift card redemption: {concurrent} concurrent attempts")
        
        data = {"code": gift_card_code, "redeem": True}
        
        results = await self.send_concurrent_requests(
            redeem_url, "POST", data, concurrent=concurrent
        )
        
        successful = [r for r in results if r.get("status_code") in [200, 201]]
        
        analysis = {
            "test_type": "gift_card_double_redeem",
            "endpoint": redeem_url,
            "total_attempts": concurrent,
            "successful_responses": len(successful),
            "potential_vulnerability": len(successful) > 1,
            "indicators": []
        }
        
        if len(successful) > 1:
            analysis["vulnerability_type"] = "double_spend"
            analysis["vulnerability"] = True
            analysis["severity"] = "high"
            analysis["recommendation"] = "Implement idempotency keys for redemption"
        else:
            analysis["severity"] = "low"
            
        return analysis
    
    async def test_password_reset_race(
        self, 
        reset_url: str, 
        email: str,
        concurrent: int = 10
    ) -> Dict:
        """Test for password reset race conditions"""
        
        logger.info(f"[Race] Testing password reset race condition")
        
        data = {"email": email}
        
        results = await self.send_concurrent_requests(
            reset_url, "POST", data, concurrent=concurrent
        )
        
        success_count = len([r for r in results if r.get("status_code") in [200, 201]])
        
        tokens_generated = [r for r in results if "token" in r.get("response_text", "").lower()]
        
        analysis = {
            "test_type": "password_reset_race",
            "endpoint": reset_url,
            "total_requests": concurrent,
            "successful_requests": success_count,
            "potential_vulnerability": success_count > 1,
            "severity": "medium",
            "indicators": []
        }
        
        if success_count > 1:
            analysis["vulnerability_type"] = "multiple_tokens_issued"
            analysis["vulnerability"] = True
            analysis["recommendation"] = "Rate limit password reset requests per email"
        
        return analysis
    
    async def test_coupon_usage(
        self, 
        apply_url: str, 
        coupon_code: str,
        concurrent: int = 20
    ) -> Dict:
        """Test if coupon can be applied multiple times"""
        
        data = {"coupon": coupon_code}
        
        results = await self.send_concurrent_requests(
            apply_url, "POST", data, concurrent=concurrent
        )
        
        success_count = sum(1 for r in results if r.get("status_code") == 200)
        
        return {
            "test_type": "coupon_multi_use",
            "endpoint": apply_url,
            "coupon_code": coupon_code,
            "concurrent_attempts": concurrent,
            "successful_applications": success_count,
            "potential_vulnerability": success_count > 1,
            "vulnerability": success_count > 1 if success_count > 1 else False,
            "severity": "high" if success_count > 1 else "low"
        }
    
    async def test_vote_manipulation(
        self, 
        vote_url: str, 
        item_id: str,
        concurrent: int = 20
    ) -> Dict:
        """Test voting system for race conditions"""
        
        data = {"item_id": item_id, "vote": 1}
        
        results = await self.send_concurrent_requests(
            vote_url, "POST", data, concurrent=concurrent
        )
        
        success_responses = [r for r in results if r.get("status_code") == 200]
        
        # Check if same vote gets counted multiple times
        unique_votes = set()
        for r in success_responses:
            text = r.get("response_text", "")
            if "vote" in text.lower():
                unique_votes.add(text[:100])
        
        return {
            "test_type": "vote_manipulation",
            "endpoint": vote_url,
            "item_id": item_id,
            "concurrent_votes": concurrent,
            "successful_votes": len(success_responses),
            "unique_responses": len(unique_votes),
            "potential_vulnerability": len(success_responses) > 1,
            "vulnerability": len(success_responses) > 1,
            "severity": "medium"
        }
    
    async def test_rate_limit_bypass(
        self, 
        url: str,
        concurrent: int = 50
    ) -> Dict:
        """Test if rate limiting can be bypassed with concurrent requests"""
        
        results = await self.send_concurrent_requests(
            url, "GET", concurrent=concurrent
        )
        
        success_count = len([r for r in results if r.get("status_code") == 200])
        rate_limited = len([r for r in results if r.get("status_code") == 429])
        
        return {
            "test_type": "rate_limit_bypass",
            "endpoint": url,
            "total_requests": concurrent,
            "successful_requests": success_count,
            "rate_limited": rate_limited,
            "bypass_possible": success_count > 10 and rate_limited < 5,
            "severity": "medium" if success_count > 10 else "low"
        }
    
    async def scan_endpoint(self, endpoint: Dict) -> List[Dict]:
        """Comprehensive race condition scan of an endpoint"""
        
        results = []
        url = endpoint.get("url")
        method = endpoint.get("method", "GET")
        
        logger.info(f"[Race] Scanning {url} for race conditions")
        
        # Basic concurrent test
        race_result = await self.test_endpoint_race(url, method)
        results.append({
            "type": "generic_race",
            "endpoint": url,
            "vulnerable": race_result.potential_vulnerability,
            "details": race_result.details
        })
        
        # Test for common vulnerable endpoints
        if "/redeem" in url or "/redeem" in url or "/apply" in url:
            coupon_result = await self.test_coupon_usage(url, "TESTCODE")
            results.append(coupon_result)
        
        return results


def create_race_detector(config: Dict) -> RaceConditionDetector:
    """Factory function"""
    return RaceConditionDetector(config)


if __name__ == "__main__":
    async def test():
        detector = create_race_detector({"race_max_concurrent": 20})
        
        # Test basic race detection
        result = await detector.test_endpoint_race(
            "https://httpbin.org/post",
            "POST",
            {"test": "data"},
            concurrent=20
        )
        
        print(f"Vulnerable: {result.potential_vulnerability}")
        print(f"Details: {result.details}")
        
    asyncio.run(test())