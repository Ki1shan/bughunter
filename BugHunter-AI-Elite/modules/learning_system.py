import json
import os
import hashlib
from datetime import datetime
from pathlib import Path
from modules.logging_config import logger


class LearningSystem:
    def __init__(self, db_path="learning_db.json"):
        self.db_path = db_path
        self.db = self._load_database()
        self.session_data = {}
        
    def _load_database(self):
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return self._init_database()
        return self._init_database()
    
    def _init_database(self):
        return {
            "version": "2.0",
            "successful_payloads": {},
            "endpoint_patterns": {},
            "vulnerability_history": [],
            "scan_history": [],
            "false_positives": [],
            "learned_tech": {},
            "param_effectiveness": {},
            "updated_at": None
        }
    
    def _save_database(self):
        self.db["updated_at"] = datetime.now().isoformat()
        try:
            with open(self.db_path, "w") as f:
                json.dump(self.db, f, indent=2)
        except Exception as e:
            logger.error(f"DB save error: {e}")
    
    def record_successful_payload(self, vuln_type, endpoint_pattern, payload, param, success=True):
        key = hashlib.md5(f"{vuln_type}:{payload}".encode()).hexdigest()
        
        if key not in self.db["successful_payloads"]:
            self.db["successful_payloads"][key] = {
                "vuln_type": vuln_type,
                "payload": payload[:200],
                "pattern": endpoint_pattern,
                "param": param,
                "success_count": 0,
                "first_seen": datetime.now().isoformat(),
                "last_seen": None,
                "targets": []
            }
        
        if success:
            self.db["successful_payloads"][key]["success_count"] += 1
            self.db["successful_payloads"][key]["last_seen"] = datetime.now().isoformat()
            if endpoint_pattern not in self.db["successful_payloads"][key]["targets"]:
                self.db["successful_payloads"][key]["targets"].append(endpoint_pattern)
        
        self._save_database()
    
    def get_successful_payloads(self, vuln_type=None):
        if vuln_type:
            return {
                k: v for k, v in self.db["successful_payloads"].items()
                if v["vuln_type"] == vuln_type and v["success_count"] >= 2
            }
        
        return {
            k: v for k, v in self.db["successful_payloads"].items()
            if v["success_count"] >= 2
        }
    
    def record_endpoint_pattern(self, url, method, params, tech_stack=None):
        pattern_key = self._extract_pattern(url)
        
        if pattern_key not in self.db["endpoint_patterns"]:
            self.db["endpoint_patterns"][pattern_key] = {
                "patterns": [url],
                "method": method,
                "params": params,
                "detection_count": 0,
                "tech_stack": tech_stack or [],
                "first_seen": datetime.now().isoformat()
            }
        
        self.db["endpoint_patterns"][pattern_key]["detection_count"] += 1
        
        if url not in self.db["endpoint_patterns"][pattern_key]["patterns"]:
            self.db["endpoint_patterns"][pattern_key]["patterns"].append(url)
        
        self._save_database()
    
    def _extract_pattern(self, url):
        import re
        pattern = re.sub(r'\d+', '{ID}', url)
        pattern = re.sub(r'[a-f0-9]{8,}', '{HASH}', pattern)
        pattern = re.sub(r'[\w\-]+@[\w\-.]+', '{EMAIL}', pattern)
        return pattern
    
    def get_learned_patterns(self, category=None):
        if category:
            return self.db["endpoint_patterns"].get(category, {})
        return self.db["endpoint_patterns"]
    
    def record_vulnerability(self, vuln_type, endpoint, severity, confirmed=False):
        record = {
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "severity": severity,
            "confirmed": confirmed,
            "timestamp": datetime.now().isoformat()
        }
        
        self.db["vulnerability_history"].append(record)
        
        if len(self.db["vulnerability_history"]) > 1000:
            self.db["vulnerability_history"] = self.db["vulnerability_history"][-500:]
        
        self._save_database()
        return record
    
    def get_vulnerability_stats(self, days=30):
        cutoff = datetime.now().timestamp() - (days * 86400)
        
        recent = [
            v for v in self.db["vulnerability_history"]
            if datetime.fromisoformat(v["timestamp"]).timestamp() > cutoff
        ]
        
        stats = {
            "total": len(recent),
            "confirmed": sum(1 for v in recent if v["confirmed"]),
            "by_type": {},
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }
        
        for v in recent:
            vtype = v["vuln_type"]
            stats["by_type"][vtype] = stats["by_type"].get(vtype, 0) + 1
            
            severity = v["severity"].lower()
            if severity in stats["by_severity"]:
                stats["by_severity"][severity] += 1
        
        return stats
    
    def record_false_positive(self, vuln_type, endpoint, reason):
        record = {
            "vuln_type": vuln_type,
            "endpoint": endpoint,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        }
        
        self.db["false_positives"].append(record)
        
        key = f"{vuln_type}:{endpoint}"
        if key not in self.db["param_effectiveness"]:
            self.db["param_effectiveness"][key] = {"false_positives": 0, "true_positives": 0}
        
        self.db["param_effectiveness"][key]["false_positives"] += 1
        
        self._save_database()
    
    def record_true_positive(self, vuln_type, endpoint):
        key = f"{vuln_type}:{endpoint}"
        if key not in self.db["param_effectiveness"]:
            self.db["param_effectiveness"][key] = {"false_positives": 0, "true_positives": 0}
        
        self.db["param_effectiveness"][key]["true_positives"] += 1
        self._save_database()
    
    def get_param_effectiveness(self, vuln_type=None):
        if vuln_type:
            return {
                k: v for k, v in self.db["param_effectiveness"].items()
                if k.startswith(vuln_type)
            }
        return self.db["param_effectiveness"]
    
    def record_tech_stack(self, endpoint, tech_stack):
        if endpoint not in self.db["learned_tech"]:
            self.db["learned_tech"][endpoint] = {
                "technologies": tech_stack,
                "first_seen": datetime.now().isoformat(),
                "detection_count": 1
            }
        else:
            self.db["learned_tech"][endpoint]["detection_count"] += 1
            for tech in tech_stack:
                if tech not in self.db["learned_tech"][endpoint]["technologies"]:
                    self.db["learned_tech"][endpoint]["technologies"].append(tech)
        
        self._save_database()
    
    def get_most_effective_payloads(self, vuln_type, limit=10):
        payloads = [
            p for p in self.db["successful_payloads"].values()
            if p["vuln_type"] == vuln_type and p["success_count"] >= 2
        ]
        
        payloads.sort(key=lambda x: x["success_count"], reverse=True)
        
        return payloads[:limit]
    
    def suggest_payloads_based_on_learned(self, vuln_type, endpoint_pattern):
        learned = self.get_successful_payloads(vuln_type)
        
        suggestions = []
        for payload_data in learned.values():
            if endpoint_pattern in payload_data.get("targets", []):
                suggestions.append({
                    "payload": payload_data["payload"],
                    "success_count": payload_data["success_count"],
                    "source": "learned"
                })
            elif self._is_similar_pattern(endpoint_pattern, payload_data.get("pattern", "")):
                suggestions.append({
                    "payload": payload_data["payload"],
                    "success_count": payload_data["success_count"],
                    "source": "similar_pattern"
                })
        
        return suggestions[:5]
    
    def _is_similar_pattern(self, pattern1, pattern2):
        import re
        normalized1 = re.sub(r'\d+', '{ID}', pattern1)
        normalized2 = re.sub(r'\d+', '{ID}', pattern2)
        
        return normalized1 == normalized2
    
    def record_scan_session(self, target, findings_count, duration):
        record = {
            "target": target,
            "findings": findings_count,
            "duration": duration,
            "timestamp": datetime.now().isoformat()
        }
        
        self.db["scan_history"].append(record)
        
        if len(self.db["scan_history"]) > 100:
            self.db["scan_history"] = self.db["scan_history"][-50:]
        
        self._save_database()
    
    def get_scan_history(self, limit=10):
        return self.db["scan_history"][-limit:]
    
    def export_knowledge(self, filepath="bughunter_knowledge_export.json"):
        export = {
            "successful_payloads": self.db["successful_payloads"],
            "endpoint_patterns": self.db["endpoint_patterns"],
            "param_effectiveness": self.db["param_effectiveness"],
            "exported_at": datetime.now().isoformat()
        }
        
        with open(filepath, "w") as f:
            json.dump(export, f, indent=2)
        
        logger.info(f"Knowledge exported to: {filepath}")
        return filepath


def create_learning_system(db_path="learning_db.json"):
    return LearningSystem(db_path)


def get_learned_payloads(vuln_type=None):
    system = LearningSystem()
    return system.get_successful_payloads(vuln_type)


def record_success(vuln_type, endpoint, payload, param):
    system = LearningSystem()
    pattern = system._extract_pattern(endpoint)
    system.record_successful_payload(vuln_type, pattern, payload, param, success=True)