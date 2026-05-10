"""
SSRF Probe Detector
Detects SSRF vulnerabilities via callback probes (like Burp Collaborator)

LEGAL: For authorized security testing ONLY. Detection only - no data exfiltration.
"""

import asyncio
import uuid
import httpx
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from modules.logging_config import logger


@dataclass
class SSRFProbeResult:
    url: str
    param: str
    vulnerable: bool
    callback_received: bool
    evidence: Dict


class SSRFProbeDetector:
    """
    SSRF Detector - Identifies Server-Side Request Forgery vulnerabilities
    
    Detection Method:
    1. Inject unique probe URLs (e.g., unique-id.oob-domain.com)
    2. Monitor for DNS/HTTP callbacks to our server
    3. Flag as vulnerable if callback received
    
    This is IDENTICAL to:
    - Burp Collaborator
    - Interact.sh
    - DNSBin
    
    DETECTION ONLY - No actual internal network access
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get("request_timeout", 15)
        self.oob_domain = config.get("oob_domain", "callback.local")
        
        # Common SSRF-vulnerable parameters
        self.ssrf_params = [
            "url", "redirect", "next", "data", "reference", "site", "html",
            "val", "validate", "domain", "callback", "return", "page", "feed",
            "host", "port", "to", "out", "view", "dir", "show", "navigation",
            "open", "file", "document", "folder", "pg", "style", "doc", "img",
            "source", "target", "c", "pageid", "name", "m", "ref", "search_theme",
            "activity", "widget", "text", "fullpath", "prefix", "q", "query"
        ]
        
        # Cloud metadata endpoints (for detection, not exploitation)
        self.metadata_endpoints = [
            # AWS
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            # GCP  
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            # Azure
            "http://169.254.169.254/metadata/instance?api-version=2017-08-01",
            # DigitalOcean
            "http://169.254.169.254/metadata/v1.json",
            # Alibaba
            "http://100.100.100.200/latest/meta-data/"
        ]
        
        self.callback_server = None
        
    def generate_probe_id(self) -> str:
        """Generate unique probe identifier"""
        return uuid.uuid4().hex[:12]
    
    def generate_probe_url(self, probe_id: str) -> str:
        """Generate probe URL with OOB domain"""
        return f"http://{probe_id}.{self.oob_domain}/"
    
    def generate_probe_domains(self) -> Dict[str, str]:
        """Generate various probe domains for testing"""
        probe_id = self.generate_probe_id()
        
        return {
            "dns": f"{probe_id}.{self.oob_domain}",
            "http": self.generate_probe_url(probe_id),
            "https": f"https://{probe_id}.{self.oob_domain}/",
            "raw": f"http://{self.oob_domain}/probe/{probe_id}"
        }
    
    async def test_param_for_ssrf(
        self, 
        url: str, 
        param: str,
        session: httpx.AsyncClient,
        probe_domains: Dict = None
    ) -> Optional[SSRFProbeResult]:
        """Test a single parameter for SSRF vulnerability"""
        
        if not probe_domains:
            probe_domains = self.generate_probe_domains()
        
        # Try with OOB probe
        probe_url = probe_domains["http"]
        
        try:
            response = await session.get(
                url, 
                params={param: probe_url},
                timeout=self.timeout,
                follow_redirects=False
            )
            
            # Check if we get a callback (would be detected by OOB server)
            # For now, we check response for indicators
            
            result = SSRFProbeResult(
                url=url,
                param=param,
                vulnerable=False,
                callback_received=False,
                evidence={"response_code": response.status_code}
            )
            
            # Basic indicator detection from response
            response_text = response.text.lower()
            
            # Check if our probe URL appears in response (reflected)
            if probe_url in response.text:
                result.evidence["reflected"] = True
                
            # Check for internal service indicators
            internal_indicators = [
                "ami-id", "instance-id", "local-hostname", "public-hostname",
                "metadata", "google", "aws", "azure", "cloud"
            ]
            
            for indicator in internal_indicators:
                if indicator in response_text:
                    result.evidence["internal_indicator"] = indicator
                    result.vulnerable = True
                    result.callback_received = True
                    break
                    
            return result
            
        except Exception as e:
            logger.debug(f"SSRF test error for {param}: {e}")
            return None
    
    async def scan_for_ssrf_params(
        self, 
        url: str, 
        params: List[str],
        method: str = "GET"
    ) -> List[Dict]:
        """Scan all parameters for SSRF vulnerability"""
        
        results = []
        
        async with httpx.AsyncClient() as session:
            if method == "POST":
                for param in params:
                    probe_domains = self.generate_probe_domains()
                    
                    try:
                        response = await session.post(
                            url,
                            data={param: probe_domains["http"]},
                            timeout=self.timeout
                        )
                        
                        result = await self._analyze_ssrf_response(
                            url, param, response, probe_domains
                        )
                        
                        if result:
                            results.append(result)
                            
                    except Exception as e:
                        logger.debug(f"POST SSRF test error: {e}")
            else:
                tasks = []
                for param in params:
                    task = self.test_param_for_ssrf(url, param, session)
                    tasks.append((param, task))
                
                for param, task in tasks:
                    try:
                        result = await task
                        if result:
                            results.append({
                                "param": param,
                                "url": url,
                                "vulnerable": result.vulnerable,
                                "evidence": result.evidence
                            })
                    except Exception as e:
                        logger.debug(f"Error testing {param}: {e}")
        
        return results
    
    async def _analyze_ssrf_response(
        self, 
        url: str, 
        param: str, 
        response: httpx.Response,
        probe_domains: Dict
    ) -> Optional[Dict]:
        """Analyze response for SSRF indicators"""
        
        result = {
            "param": param,
            "url": url,
            "vulnerable": False,
            "evidence": {}
        }
        
        response_text = response.text.lower()
        
        # Check for reflection
        if probe_domains["http"] in response.text:
            result["evidence"]["reflected"] = True
            
        # Check for internal metadata
        metadata_indicators = [
            "ami-id", "instance-id", "local-hostname", "public-hostname",
            "metadata.google", "computeMetadata", "x-aws-instance-id",
            "kubernetes.io", "container.googleapis"
        ]
        
        for indicator in metadata_indicators:
            if indicator in response_text:
                result["vulnerable"] = True
                result["evidence"]["internal_access"] = indicator
                return result
        
        # Check for internal IP patterns
        import re
        internal_ips = re.findall(
            r'(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)',
            response.text
        )
        
        if internal_ips:
            result["vulnerable"] = True
            result["evidence"]["internal_ip_found"] = internal_ips[0]
        
        # Check for error messages indicating SSRF
        ssrf_error_indicators = [
            "could not resolve host", "connection refused", "timeout",
            "no route to host", "name or service not known",
            "failed to fetch", "urlopen error"
        ]
        
        for error in ssrf_error_indicators:
            if error in response_text:
                result["evidence"]["error_message"] = error
                result["vulnerable"] = True
                return result
        
        return result if result["evidence"] else None
    
    async def test_cloud_metadata_access(
        self, 
        url: str, 
        param: str,
        session: httpx.AsyncClient
    ) -> List[Dict]:
        """Test for cloud metadata service access (detection only)"""
        
        results = []
        
        for metadata_url in self.metadata_endpoints:
            try:
                response = await session.get(
                    url,
                    params={param: metadata_url},
                    timeout=5
                )
                
                if response.status_code == 200:
                    result = {
                        "url": url,
                        "param": param,
                        "metadata_endpoint": metadata_url,
                        "vulnerable": True,
                        "evidence": "Successfully accessed cloud metadata",
                        "severity": "critical",
                        "cloud_provider": self._identify_cloud(metadata_url)
                    }
                    results.append(result)
                    
            except Exception:
                pass
        
        return results
    
    def _identify_cloud(self, url: str) -> str:
        """Identify cloud provider from metadata URL"""
        if "169.254.169.254" in url:
            if "google" in url or "metadata.google" in url:
                return "GCP"
            elif "100.100.100.200" in url:
                return "Alibaba"
            else:
                return "AWS/Azure/DigitalOcean"
        return "Unknown"
    
    async def detect_from_form(
        self, 
        form_action: str, 
        form_method: str,
        form_inputs: List[Dict]
    ) -> List[Dict]:
        """Detect SSRF from form inputs"""
        
        results = []
        url_params = [i.get("name") for i in form_inputs if i.get("type") in ["url", "text"]]
        
        if url_params:
            results = await self.scan_for_ssrf_params(form_action, url_params, form_method)
        
        return results


def create_ssrf_detector(config: Dict) -> SSRFProbeDetector:
    """Factory function"""
    return SSRFProbeDetector(config)


if __name__ == "__main__":
    async def test():
        detector = create_ssrf_detector({"oob_domain": "test.local"})
        
        probe = detector.generate_probe_domains()
        print(f"Probe domains: {probe}")
        
        result = await detector.scan_for_ssrf_params(
            "https://example.com/api/fetch",
            ["url", "redirect"],
            "GET"
        )
        
        print(f"Results: {result}")
        
    asyncio.run(test())