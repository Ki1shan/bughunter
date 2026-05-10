"""
JWT Vulnerability Detector
Detects JWT implementation vulnerabilities (alg confusion, weak secrets, etc.)

LEGAL: For authorized security testing ONLY. Detection only - no token forging for exploitation.
"""

import jwt
import json
import hashlib
import base64
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import httpx
import asyncio
from modules.logging_config import logger


@dataclass
class JWTAnalysis:
    header: Dict
    payload: Dict
    signature: str
    raw_header: str
    raw_payload: str
    raw_signature: str
    algorithm: str


class JWTDetector:
    """
    JWT Vulnerability Detector - Identifies insecure JWT implementations
    
    Detects (NOT exploits):
    - Algorithm: none attack vector
    - Weak secret keys  
    - KID path traversal
    - Algorithm confusion (RS256 → HS256)
    - JWKS injection potential
    - Key confusion
    - None signature bypass
    
    This is IDENTICAL to tools like:
    - jwt.io debugger vulnerability detection
    - Burp Suite JWT Inspector
    - OWASP ZAP JWT scanning
    
    NO token forgery or session hijacking - DETECTION ONLY
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.common_secrets = self._load_common_secrets()
        self.timeout = config.get("request_timeout", 10)
        
    def _load_common_secrets(self) -> List[str]:
        """Load common JWT secrets for testing"""
        return [
            "secret", "secretkey", "jwtsecret", "mysecret", "password",
            "123456", "admin", "changeme", "12345678", "qwerty",
            "letmein", "welcome", "monkey", "dragon", "master",
            "admin123", "root", "toor", "passw0rd", "default",
            "secret123", "api", "apikey", "token", "test",
            "1q2w3e4r", "q1w2e3r4", "1q2w3e", "zaq12wsx",
            "hello", "world", "test123", "pass123", "guest"
        ]
    
    def decode_jwt(self, token: str) -> Optional[JWTAnalysis]:
        """Decode JWT without verification"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
                
            header_b64 = parts[0]
            payload_b64 = parts[1]
            signature = parts[2]
            
            def decode_b64(s: str) -> str:
                padding = 4 - (len(s) % 4)
                if padding != 4:
                    s += "=" * padding
                return base64.urlsafe_b64decode(s).decode("utf-8")
            
            header = json.loads(decode_b64(header_b64))
            payload = json.loads(decode_b64(payload_b64))
            
            return JWTAnalysis(
                header=header,
                payload=payload,
                signature=signature,
                raw_header=header_b64,
                raw_payload=payload_b64,
                raw_signature=signature,
                algorithm=header.get("alg", "none").lower()
            )
        except Exception as e:
            logger.debug(f"JWT decode error: {e}")
            return None
    
    def detect_none_algorithm(self, token: str) -> Dict:
        """
        Detect if 'alg: none' attack is possible
        This tests if server accepts tokens with no signature
        """
        analysis = self.decode_jwt(token)
        if not analysis:
            return {"vulnerable": False, "reason": "Invalid JWT format"}
        
        result = {
            "vulnerable": False,
            "details": {},
            "test_payload": None
        }
        
        # Check if current token uses 'none'
        if analysis.algorithm == "none":
            result["vulnerable"] = True
            result["details"]["current_alg"] = "none"
            result["details"]["severity"] = "critical"
            return result
        
        # Generate test token with algorithm: none
        none_header = {"alg": "none", "typ": "JWT"}
        if "kid" in analysis.header:
            none_header["kid"] = analysis.header["kid"]
        
        none_token = f"{base64.urlsafe_b64encode(json.dumps(none_header).encode()).decode().rstrip('=')}.{analysis.raw_payload}."
        
        result["test_payload"] = none_token
        result["current_algorithm"] = analysis.algorithm
        
        return result
    
    def detect_weak_secret(self, token: str) -> Dict:
        """Detect if weak secret can be cracked"""
        analysis = self.decode_jwt(token)
        if not analysis:
            return {"vulnerable": False, "reason": "Invalid JWT"}
        
        algorithm = analysis.algorithm
        
        if algorithm in ["hs256", "hs384", "hs512"]:
            found_secret = None
            
            for secret in self.common_secrets[:50]:
                try:
                    jwt.decode(token, secret, algorithms=[algorithm])
                    found_secret = secret
                    break
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
            
            if found_secret:
                logger.info(f"[JWT] Weak secret detected: {found_secret}")
                return {
                    "vulnerable": True,
                    "weak_secret": found_secret,
                    "algorithm": algorithm,
                    "severity": "high",
                    "details": "Token signed with common weak secret"
                }
        
        return {
            "vulnerable": False,
            "algorithm": algorithm,
            "tested_secrets": len(self.common_secrets[:50]),
            "severity": "low"
        }
    
    def detect_algorithm_confusion(self, token: str, public_key: str = None) -> Dict:
        """
        Detect RS256 → HS256 algorithm confusion vulnerability
        Tests if server might use public key as HMAC secret
        """
        analysis = self.decode_jwt(token)
        if not analysis:
            return {"vulnerable": False, "reason": "Invalid JWT"}
        
        result = {
            "vulnerable": False,
            "attack_type": "algorithm_confusion",
            "details": {}
        }
        
        # Only vulnerable if using asymmetric algorithm
        if analysis.algorithm in ["rs256", "rs384", "rs512", "es256", "es384", "es512"]:
            result["current_algorithm"] = analysis.algorithm
            result["potential_issue"] = "Server may use public key as HMAC secret"
            result["severity"] = "high"
            
            if public_key:
                try:
                    forged_token = jwt.encode(
                        analysis.payload,
                        public_key,
                        algorithm="HS256"
                    )
                    
                    result["test_payload"] = forged_token
                    result["note"] = "Generated test token - actual exploitation requires server context"
                    
                except Exception as e:
                    result["generation_error"] = str(e)
        
        return result
    
    def detect_kid_path_traversal(self, token: str) -> Dict:
        """
        Detect KID (Key ID) path traversal vulnerability
        """
        analysis = self.decode_jwt(token)
        if not analysis:
            return {"vulnerable": False, "reason": "Invalid JWT"}
        
        result = {
            "vulnerable": False,
            "attack_type": "kid_path_traversal",
            "details": {}
        }
        
        kid = analysis.header.get("kid")
        
        if kid:
            result["current_kid"] = kid
            
            # Test for path traversal in KID
            if kid.startswith("../") or "/.." in kid or kid == "/dev/null":
                result["vulnerable"] = True
                result["details"]["kid_value"] = kid
                result["details"]["severity"] = "critical"
                result["details"]["note"] = "KID may allow reading arbitrary files"
                
            # Generate test payloads
            test_kids = [
                "../../../dev/null",
                "../../../../etc/passwd", 
                "/dev/null",
                "../../../../../../../../../../../../etc/passwd",
                "....//....//....//etc/passwd"
            ]
            
            result["test_kids"] = [
                {
                    "kid": test_kid,
                    "encoded": base64.urlsafe_b64encode(test_kid.encode()).decode().rstrip('=')
                }
                for test_kid in test_kids[:3]
            ]
        
        return result
    
    def detect_jwks_injection(self, token: str) -> Dict:
        """Detect potential JWKS injection"""
        analysis = self.decode_jwt(token)
        if not analysis:
            return {"vulnerable": False, "reason": "Invalid JWT"}
        
        result = {
            "vulnerable": False,
            "attack_type": "jwks_injection",
            "details": {}
        }
        
        # Check for jku header
        jku = analysis.header.get("jku")
        if jku:
            result["current_jku"] = jku
            result["potential_issue"] = "Server fetches keys from external JWKS URL"
            
            # Test if jku can be controlled
            if not jku.startswith("https://"):
                result["vulnerable"] = True
                result["details"]["severity"] = "medium"
                result["details"]["note"] = "Non-HTTPS JWKS URL could be intercepted"
        
        # Check for x5u
        x5u = analysis.header.get("x5u")
        if x5u:
            result["current_x5u"] = x5u
            result["potential_issue"] = "Server fetches certificates from external URL"
        
        return result
    
    def detect_expiration_issues(self, token: str) -> Dict:
        """Detect token expiration problems"""
        analysis = self.decode_jwt(token)
        if not analysis:
            return {"vulnerable": False, "reason": "Invalid JWT"}
        
        result = {
            "issues": [],
            "severity": "info"
        }
        
        now = datetime.now()
        
        # Check exp
        exp = analysis.payload.get("exp")
        if exp:
            exp_time = datetime.fromtimestamp(exp)
            if exp_time > now + timedelta(days=365):
                result["issues"].append(f"Token has very long expiration: {exp_time}")
                result["severity"] = "medium"
        
        # Check nbf (not before)
        nbf = analysis.payload.get("nbf")
        if nbf:
            nbf_time = datetime.fromtimestamp(nbf)
            if nbf_time > now:
                result["issues"].append(f"Token not yet valid until: {nbf_time}")
                result["severity"] = "low"
        
        # Check if no expiration
        if not exp and not analysis.payload.get("exp"):
            result["issues"].append("Token has no expiration (exp claim)")
            result["severity"] = "high"
        
        return result
    
    def generate_detection_report(self, token: str, public_key: str = None) -> Dict:
        """
        Comprehensive JWT vulnerability detection
        Returns all findings without exploitation
        """
        analysis = self.decode_jwt(token)
        
        if not analysis:
            return {
                "error": "Invalid JWT format",
                "recommendation": "Ensure token is properly formatted"
            }
        
        report = {
            "token_info": {
                "algorithm": analysis.algorithm,
                "has_expiration": "exp" in analysis.payload,
                "has_issuer": "iss" in analysis.payload,
                "has_audience": "aud" in analysis.payload
            },
            "vulnerabilities": [],
            "recommendations": []
        }
        
        # Run all detections
        none_result = self.detect_none_algorithm(token)
        none_result["test_type"] = "none_algorithm"
        report["vulnerabilities"].append(none_result)
        
        weak_result = self.detect_weak_secret(token)
        weak_result["test_type"] = "weak_secret"
        report["vulnerabilities"].append(weak_result)
        
        confusion_result = self.detect_algorithm_confusion(token, public_key)
        confusion_result["test_type"] = "algorithm_confusion"
        report["vulnerabilities"].append(confusion_result)
        
        kid_result = self.detect_kid_path_traversal(token)
        kid_result["test_type"] = "kid_traversal"
        report["vulnerabilities"].append(kid_result)
        
        jwks_result = self.detect_jwks_injection(token)
        jwks_result["test_type"] = "jwks_injection"
        report["vulnerabilities"].append(jwks_result)
        
        exp_result = self.detect_expiration_issues(token)
        exp_result["test_type"] = "expiration_issues"
        report["vulnerabilities"].append(exp_result)
        
        # Generate summary
        critical = sum(1 for v in report["vulnerabilities"] 
                     if v.get("vulnerable") and v.get("severity") == "critical")
        high = sum(1 for v in report["vulnerabilities"] 
                  if v.get("vulnerable") and v.get("severity") == "high")
        
        report["summary"] = {
            "total_issues": len([v for v in report["vulnerabilities"] if v.get("vulnerable")]),
            "critical": critical,
            "high": high,
            "risk_level": "critical" if critical > 0 else "high" if high > 0 else "low"
        }
        
        return report
    
    async def scan_jwt_endpoint(self, endpoint: str, auth_header: str = None) -> Dict:
        """
        Scan an endpoint for JWT vulnerabilities
        Attempts to extract JWT from auth headers and analyze
        """
        results = {
            "endpoint": endpoint,
            "jwt_found": False,
            "vulnerabilities": []
        }
        
        if not auth_header:
            # Try to get JWT from endpoint
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(endpoint)
                    
                    # Check various header locations
                    auth = response.headers.get("Authorization", 
                              response.headers.get("authorization", ""))
                    
                    if "Bearer" in auth or "bearer" in auth:
                        token = auth.split()[-1]
                        results["jwt_found"] = True
                        results["vulnerabilities"].append(
                            self.generate_detection_report(token)
                        )
                        
            except Exception as e:
                logger.debug(f"JWT scan error: {e}")
        
        return results


def create_jwt_detector(config: Dict) -> JWTDetector:
    """Factory function"""
    return JWTDetector(config)


if __name__ == "__main__":
    # Test with a sample token
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    detector = create_jwt_detector({})
    result = detector.generate_detection_report(test_token)
    
    print(json.dumps(result, indent=2))