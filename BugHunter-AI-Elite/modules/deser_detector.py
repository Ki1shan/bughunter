"""
Insecure Deserialization Detector - Identifies deserialization vulnerabilities

LEGAL: For authorized security testing ONLY. Detection only - no actual exploitation.
"""

import asyncio
import httpx
import base64
import pickle
import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
from modules.logging_config import logger


@dataclass
class DeserTestResult:
    url: str
    param: str
    format: str
    vulnerable: bool
    evidence: Dict


class DeserializationDetector:
    """
    Insecure Deserialization Detector
    
    Detects potential insecure deserialization by:
    1. Testing with malformed serialized data
    2. Analyzing error messages for技术泄露
    3. Detecting unsafe deserialization patterns
    
    Standard detection methodology - used by all scanners
    
    DETECTION ONLY - No actual code execution
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get("request_timeout", 15)
        
        # Test payloads for different languages/frameworks
        self.test_payloads = {
            "python_pickle": [
                # Malformed pickle
                b"c__builtin__\nops\n.",
                # Invalid opcode
                b"\x80\xff\n.",
                # Empty payload
                b"",
                b"invalid",
                # Base64 of malformed
            ],
            "python_yaml": [
                "!!python/object/apply:builtins.print",
                "!!python/object/apply:os.system",
                "!!python/object/apply:subprocess.call",
                "!!python/object:__main__.EvilClass",
                "!!python/object/apply:pickle.loads"
            ],
            "java_serial": [
                # Base64 encoded serialized Java objects
                "rO0ABXNyABpodWRwLmNyeXB0by5TY3JpcHRTaGVsbA==",
                "AAcAAQAAAAEAQAACgAAAAYAAAA=",
                "base64_serialied_java_object"
            ],
            "ruby_marshal": [
                "\x04\x08o:@Evil\x00",
                "Marshal.dump({evil: true})"
            ],
            "php_object": [
                "O:8:\"EvilClass\":0:{}",
                "O:7:\"PDO\":0:{}",
                "a:1:{s:4:\"evil\";s:4:\"test\";}",
                "serialize(array)"
            ],
            "dotnet_binary": [
                "binary_serialized_data",
                "BinaryFormatter_deserialized"
            ]
        }
        
        # Error indicators for different languages
        self.error_patterns = {
            "python": [
                "pickle.UnpicklingError",
                "AttributeError",
                "ModuleNotFoundError", 
                "TypeError",
                "EOFError",
                "__import__",
                "RuntimeError",
                "yaml.YAMLError",
                "constructor",
                "has no attribute"
            ],
            "java": [
                "ClassNotFoundException",
                "java.lang.ClassNotFound",
                "InvalidClassException",
                "java.io.InvalidClassException",
                "ObjectStreamException",
                "SerialException",
                "InvocationTargetException",
                "ClassLoader"
            ],
            "ruby": [
                "TypeError",
                "ArgumentError",
                "Marshal.load",
                "undefined method",
                "unauthorized method"
            ],
            "php": [
                "unserialize",
                "Serializable",
                "ErrorException",
                "ClassNotFound"
            ],
            "dotnet": [
                "BinaryFormatter",
                "SerializationException",
                "InvalidOperationException",
                "IO.FileNotFoundException"
            ]
        }
        
    async def test_python_pickle(
        self,
        url: str,
        param: str,
        session: httpx.AsyncClient
    ) -> Optional[DeserTestResult]:
        """Test for insecure Python pickle deserialization"""
        
        for payload in self.test_payloads["python_pickle"][:2]:
            try:
                encoded = base64.b64encode(payload).decode()
                
                response = await session.post(
                    url,
                    data={param: encoded},
                    timeout=self.timeout
                )
                
                result = await self._analyze_response(
                    url, param, response, "python_pickle"
                )
                
                if result and result.vulnerable:
                    return result
                    
            except Exception as e:
                logger.debug(f"Pickle test error: {e}")
        
        return None
    
    async def test_python_yaml(
        self,
        url: str,
        param: str,
        session: httpx.AsyncClient
    ) -> Optional[DeserTestResult]:
        """Test for insecure YAML deserialization"""
        
        for payload in self.test_payloads["python_yaml"][:3]:
            try:
                # Try as direct parameter
                response = await session.post(
                    url,
                    data={param: payload},
                    timeout=self.timeout
                )
                
                result = await self._analyze_response(
                    url, param, response, "python_yaml"
                )
                
                if result and result.vulnerable:
                    return result
                    
            except Exception as e:
                logger.debug(f"YAML test error: {e}")
        
        return None
    
    async def test_java_deserialization(
        self,
        url: str,
        param: str,
        session: httpx.AsyncClient
    ) -> Optional[DeserTestResult]:
        """Test for insecure Java deserialization"""
        
        for payload in self.test_payloads["java_serial"]:
            try:
                # Try as request body
                headers = {"Content-Type": "application/x-java-serialized-object"}
                
                response = await session.post(
                    url,
                    content=payload,
                    headers=headers,
                    timeout=self.timeout
                )
                
                result = await self._analyze_response(
                    url, param, response, "java_serial"
                )
                
                if result and result.vulnerable:
                    return result
                    
            except Exception as e:
                logger.debug(f"Java deser test error: {e}")
        
        return None
    
    async def test_php_unserialize(
        self,
        url: str,
        param: str,
        session: httpx.AsyncClient
    ) -> Optional[DeserTestResult]:
        """Test for insecure PHP unserialize"""
        
        for payload in self.test_payloads["php_object"]:
            try:
                response = await session.post(
                    url,
                    data={param: payload},
                    timeout=self.timeout
                )
                
                result = await self._analyze_response(
                    url, param, response, "php_object"
                )
                
                if result and result.vulnerable:
                    return result
                    
            except Exception as e:
                logger.debug(f"PHP test error: {e}")
        
        return None
    
    async def _analyze_response(
        self,
        url: str,
        param: str,
        response: httpx.Response,
        format: str
    ) -> Optional[DeserTestResult]:
        """Analyze response for deserialization indicators"""
        
        response_text = response.text.lower()
        status = response.status_code
        
        # Check for error messages
        lang_errors = self.error_patterns.get(format.split("_")[0], [])
        
        for error in lang_errors:
            if error.lower() in response_text:
                return DeserTestResult(
                    url=url,
                    param=param,
                    format=format,
                    vulnerable=True,
                    evidence={
                        "type": "error_message",
                        "error": error,
                        "status": status
                    }
                )
        
        # Check for stack traces
        stack_trace_indicators = [
            "traceback", "stack trace", "at line", 
            "in package", "org.springframework",
            "java.lang", "__import__"
        ]
        
        for indicator in stack_trace_indicators:
            if indicator in response_text:
                return DeserTestResult(
                    url=url,
                    param=param,
                    format=format,
                    vulnerable=True,
                    evidence={
                        "type": "stack_trace",
                        "indicator": indicator,
                        "status": status
                    }
                )
        
        # Check for deserialization library names
        lib_indicators = [
            "pickle", "yaml", "marshal", "unserialize",
            "ObjectInputStream", "ObjectMapper"
        ]
        
        for indicator in lib_indicators:
            if indicator in response_text:
                return DeserTestResult(
                    url=url,
                    param=param,
                    format=format,
                    vulnerable=True,
                    evidence={
                        "type": "library_exposure",
                        "indicator": indicator
                    }
                )
        
        return None
    
    async def scan_endpoint(
        self,
        url: str,
        params: List[str],
        method: str = "POST"
    ) -> List[Dict]:
        """Comprehensive deserialization scan"""
        
        results = []
        
        async with httpx.AsyncClient() as session:
            for param in params:
                logger.info(f"[Deser] Testing {param} at {url}")
                
                # Test Python pickle
                result = await self.test_python_pickle(url, param, session)
                if result:
                    results.append(self._result_to_dict(result))
                
                # Test Python YAML
                result = await self.test_python_yaml(url, param, session)
                if result:
                    results.append(self._result_to_dict(result))
                
                # Test Java
                result = await self.test_java_deserialization(url, param, session)
                if result:
                    results.append(self._result_to_dict(result))
                
                # Test PHP
                result = await self.test_php_unserialize(url, param, session)
                if result:
                    results.append(self._result_to_dict(result))
        
        return results
    
    def _result_to_dict(self, result: DeserTestResult) -> Dict:
        return {
            "url": result.url,
            "param": result.param,
            "format": result.format,
            "vulnerable": result.vulnerable,
            "evidence": result.evidence
        }


def create_deserialization_detector(config: Dict) -> DeserializationDetector:
    """Factory function"""
    return DeserializationDetector(config)


if __name__ == "__main__":
    detector = create_deserialization_detector({})
    print("Deserialization detector initialized")
    print(f"Test payloads configured: {list(detector.test_payloads.keys())}")