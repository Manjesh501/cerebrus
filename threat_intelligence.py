import os
import requests
import json
import time
import logging
import hashlib
try:
    import yara
except ImportError:
    yara = None
    print("YARA module not available - YARA scanning will be disabled")
from datetime import datetime, timedelta
import threading
import sqlite3
from typing import Dict, List, Optional
import configparser
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ThreatIntelligence')

class MultiSourceThreatIntelligence:
    """
    Multi-source threat intelligence integration system
    """
    
    def __init__(self, config_path="threat_intel_config.ini"):
        self.config = self._load_config(config_path)
        self.db_path = self.config.get('database', 'path', fallback='threat_intel.db')
        self.cache_timeout = int(self.config.get('cache', 'timeout_hours', fallback='24'))
        
        # Initialize database
        self._init_database()
        
        # Initialize API clients
        self.vt_client = VirusTotalClient(self.config.get('virustotal', 'api_key', fallback=''))
        self.hybrid_client = HybridAnalysisClient(self.config.get('hybrid_analysis', 'api_key', fallback=''))
        self.joe_client = JoeSandboxClient(self.config.get('joe_sandbox', 'api_key', fallback=''))
        
        # Initialize YARA engine (only if YARA is available)
        if yara:
            self.yara_engine = YARAEngine(self.config.get('yara', 'rules_path', fallback='yara_rules/'))
        else:
            self.yara_engine = None
            logger.warning("YARA module not available - YARA scanning disabled")
        
        # Initialize IOC database
        self.ioc_db = IOCDatabase(self.db_path)
        
        # Threat attribution system
        self.attribution_engine = ThreatAttributionEngine()
        
    def _load_config(self, config_path):
        """Load configuration from file"""
        config = configparser.ConfigParser()
        
        if os.path.exists(config_path):
            config.read(config_path)
        else:
            # Create default config
            self._create_default_config(config_path)
            config.read(config_path)
        
        return config
    
    def _create_default_config(self, config_path):
        """Create default configuration file"""
        config_content = """
[database]
path = threat_intel.db

[cache]
timeout_hours = 24

[virustotal]
api_key = YOUR_VT_API_KEY

[hybrid_analysis]
api_key = YOUR_HYBRID_API_KEY

[joe_sandbox]
api_key = YOUR_JOE_API_KEY

[yara]
rules_path = yara_rules/

[attribution]
enable_ml_attribution = true
confidence_threshold = 0.7
"""
        with open(config_path, 'w') as f:
            f.write(config_content)
    
    def _init_database(self):
        """Initialize SQLite database for caching"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_reports (
                hash TEXT PRIMARY KEY,
                source TEXT,
                report TEXT,
                timestamp DATETIME,
                expires DATETIME
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                indicator TEXT PRIMARY KEY,
                type TEXT,
                threat_family TEXT,
                confidence REAL,
                source TEXT,
                timestamp DATETIME
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_actors (
                name TEXT PRIMARY KEY,
                aliases TEXT,
                ttps TEXT,
                attribution_confidence REAL,
                last_activity DATETIME
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def analyze_file_multi_source(self, file_path):
        """
        Analyze file using multiple threat intelligence sources
        """
        file_hash = self._calculate_hash(file_path)
        
        results = {
            'file_hash': file_hash,
            'file_path': file_path,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'aggregated_verdict': 'unknown',
            'confidence_score': 0,
            'threat_family': 'unknown',
            'attribution': {}
        }
        
        # Check cache first
        cached_reports = self._get_cached_reports(file_hash)
        
        # VirusTotal analysis
        if 'virustotal' not in cached_reports:
            vt_result = self.vt_client.scan_file(file_path)
            if vt_result:
                results['sources']['virustotal'] = vt_result
                self._cache_report(file_hash, 'virustotal', vt_result)
        else:
            results['sources']['virustotal'] = cached_reports['virustotal']
        
        # Hybrid Analysis
        if 'hybrid_analysis' not in cached_reports:
            hybrid_result = self.hybrid_client.analyze_file(file_path)
            if hybrid_result:
                results['sources']['hybrid_analysis'] = hybrid_result
                self._cache_report(file_hash, 'hybrid_analysis', hybrid_result)
        else:
            results['sources']['hybrid_analysis'] = cached_reports['hybrid_analysis']
        
        # Joe Sandbox
        if 'joe_sandbox' not in cached_reports:
            joe_result = self.joe_client.analyze_file(file_path)
            if joe_result:
                results['sources']['joe_sandbox'] = joe_result
                self._cache_report(file_hash, 'joe_sandbox', joe_result)
        else:
            results['sources']['joe_sandbox'] = cached_reports['joe_sandbox']
        
        # YARA scanning (only if available)
        if self.yara_engine:
            yara_matches = self.yara_engine.scan_file(file_path)
            if yara_matches:
                results['sources']['yara'] = yara_matches
        
        # IOC checking
        ioc_matches = self.ioc_db.check_file_iocs(file_path)
        if ioc_matches:
            results['sources']['ioc_database'] = ioc_matches
        
        # Aggregate results
        aggregated = self._aggregate_results(results['sources'])
        results.update(aggregated)
        
        # Threat attribution
        attribution = self.attribution_engine.attribute_threat(results)
        results['attribution'] = attribution
        
        return results
    
    def _get_cached_reports(self, file_hash):
        """Get cached reports for a file hash"""
        cached_reports = {}
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT source, report FROM file_reports 
            WHERE hash = ? AND expires > datetime('now')
        ''', (file_hash,))
        
        for row in cursor.fetchall():
            source, report_json = row
            try:
                cached_reports[source] = json.loads(report_json)
            except json.JSONDecodeError:
                pass
        
        conn.close()
        return cached_reports
    
    def _cache_report(self, file_hash, source, report):
        """Cache a threat intelligence report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        expires = datetime.now() + timedelta(hours=self.cache_timeout)
        
        cursor.execute('''
            INSERT OR REPLACE INTO file_reports 
            (hash, source, report, timestamp, expires)
            VALUES (?, ?, ?, datetime('now'), ?)
        ''', (file_hash, source, json.dumps(report), expires))
        
        conn.commit()
        conn.close()
    
    def _aggregate_results(self, sources):
        """Aggregate results from multiple sources"""
        total_detections = 0
        total_engines = 0
        threat_families = {}
        confidence_scores = []
        
        # VirusTotal aggregation
        if 'virustotal' in sources:
            vt = sources['virustotal']
            if 'positives' in vt and 'total' in vt:
                total_detections += vt['positives']
                total_engines += vt['total']
                confidence_scores.append(vt['positives'] / vt['total'] if vt['total'] > 0 else 0)
        
        # Hybrid Analysis aggregation
        if 'hybrid_analysis' in sources:
            hybrid = sources['hybrid_analysis']
            if 'threat_score' in hybrid:
                confidence_scores.append(hybrid['threat_score'] / 100)
            if 'malware_family' in hybrid:
                threat_families[hybrid['malware_family']] = threat_families.get(hybrid['malware_family'], 0) + 1
        
        # Joe Sandbox aggregation
        if 'joe_sandbox' in sources:
            joe = sources['joe_sandbox']
            if 'detection' in joe:
                if joe['detection'] == 'malicious':
                    confidence_scores.append(0.8)
                elif joe['detection'] == 'suspicious':
                    confidence_scores.append(0.5)
        
        # YARA aggregation
        if 'yara' in sources:
            yara_matches = sources['yara']
            if yara_matches:
                confidence_scores.append(0.9)  # High confidence for YARA matches
                for match in yara_matches:
                    family = match.get('family', 'unknown')
                    threat_families[family] = threat_families.get(family, 0) + 1
        
        # IOC aggregation
        if 'ioc_database' in sources:
            ioc_matches = sources['ioc_database']
            if ioc_matches:
                confidence_scores.append(0.8)
        
        # Determine verdict
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        if avg_confidence > 0.7:
            verdict = 'malicious'
        elif avg_confidence > 0.3:
            verdict = 'suspicious'
        else:
            verdict = 'clean'
        
        # Determine most likely threat family
        most_common_family = max(threat_families.items(), key=lambda x: x[1])[0] if threat_families else 'unknown'
        
        return {
            'aggregated_verdict': verdict,
            'confidence_score': avg_confidence,
            'threat_family': most_common_family,
            'detection_ratio': f"{total_detections}/{total_engines}" if total_engines > 0 else "0/0"
        }
    
    def _calculate_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

class VirusTotalClient:
    """VirusTotal API client"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.session = requests.Session()
        
    def scan_file(self, file_path):
        """Scan file with VirusTotal"""
        if not self.api_key:
            return None
        
        try:
            # Calculate file hash
            file_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
            
            # Check existing report
            params = {
                'apikey': self.api_key,
                'resource': file_hash.hexdigest()
            }
            
            response = self.session.get(f"{self.base_url}/file/report", params=params)
            
            if response.status_code == 200:
                return response.json()
            
        except Exception as e:
            logger.error(f"VirusTotal API error: {e}")
        
        return None

class HybridAnalysisClient:
    """Hybrid Analysis API client"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        
    def analyze_file(self, file_path):
        """Analyze file with Hybrid Analysis"""
        if not self.api_key:
            return None
        
        try:
            # Implementation would go here
            # This is a placeholder for demonstration
            return {
                'threat_score': 75,
                'malware_family': 'Trojan',
                'verdict': 'malicious'
            }
            
        except Exception as e:
            logger.error(f"Hybrid Analysis API error: {e}")
        
        return None

class JoeSandboxClient:
    """Joe Sandbox API client"""
    
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://jbxcloud.joesecurity.org/api"
        
    def analyze_file(self, file_path):
        """Analyze file with Joe Sandbox"""
        if not self.api_key:
            return None
        
        try:
            # Implementation would go here
            # This is a placeholder for demonstration
            return {
                'detection': 'malicious',
                'threat_family': 'Backdoor',
                'score': 8
            }
            
        except Exception as e:
            logger.error(f"Joe Sandbox API error: {e}")
        
        return None

class YARAEngine:
    """YARA rule engine for signature-based detection"""
    
    def __init__(self, rules_path):
        self.rules_path = rules_path
        self.compiled_rules = self._compile_rules()
        
    def _compile_rules(self):
        """Compile YARA rules from directory"""
        if not yara:
            logger.warning("YARA module not available, cannot compile rules")
            return None
            
        try:
            if not os.path.exists(self.rules_path):
                os.makedirs(self.rules_path)
                self._create_sample_rules()
            
            rule_files = {}
            for filename in os.listdir(self.rules_path):
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    rule_path = os.path.join(self.rules_path, filename)
                    rule_files[filename] = rule_path
            
            if rule_files:
                return yara.compile(filepaths=rule_files)
            
        except Exception as e:
            logger.error(f"YARA compilation error: {e}")
        
        return None
    
    def _create_sample_rules(self):
        """Create sample YARA rules"""
        sample_rules = """
rule Suspicious_CreateRemoteThread
{
    meta:
        description = "Detects CreateRemoteThread API call"
        family = "injection"
        
    strings:
        $api = "CreateRemoteThread"
        
    condition:
        $api
}

rule Ransomware_Keywords
{
    meta:
        description = "Detects ransomware-related keywords"
        family = "ransomware"
        
    strings:
        $ransom1 = "ransom" nocase
        $ransom2 = "bitcoin" nocase
        $ransom3 = "decrypt" nocase
        $ransom4 = "payment" nocase
        
    condition:
        any of them
}

rule Trojan_Backdoor
{
    meta:
        description = "Detects backdoor functionality"
        family = "trojan"
        
    strings:
        $backdoor1 = "backdoor" nocase
        $backdoor2 = "remote access" nocase
        $backdoor3 = "shell" nocase
        
    condition:
        any of them
}
"""
        
        with open(os.path.join(self.rules_path, 'sample_rules.yar'), 'w') as f:
            f.write(sample_rules)
    
    def scan_file(self, file_path):
        """Scan file with YARA rules"""
        if not self.compiled_rules:
            return []
        
        try:
            matches = self.compiled_rules.match(file_path)
            
            results = []
            for match in matches:
                result = {
                    'rule_name': match.rule,
                    'family': match.meta.get('family', 'unknown'),
                    'description': match.meta.get('description', ''),
                    'strings': [str(s) for s in match.strings]
                }
                results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"YARA scanning error: {e}")
        
        return []

class IOCDatabase:
    """Indicators of Compromise database"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self._update_iocs()
        
    def _update_iocs(self):
        """Update IOCs from threat feeds"""
        try:
            # Sample IOCs - in production, these would come from threat feeds
            sample_iocs = [
                {
                    'indicator': '1a2b3c4d5e6f7890abcdef1234567890',
                    'type': 'md5',
                    'threat_family': 'trojan',
                    'confidence': 0.9,
                    'source': 'sample_feed'
                },
                {
                    'indicator': 'malicious.example.com',
                    'type': 'domain',
                    'threat_family': 'c2',
                    'confidence': 0.8,
                    'source': 'sample_feed'
                }
            ]
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for ioc in sample_iocs:
                cursor.execute('''
                    INSERT OR REPLACE INTO iocs 
                    (indicator, type, threat_family, confidence, source, timestamp)
                    VALUES (?, ?, ?, ?, ?, datetime('now'))
                ''', (ioc['indicator'], ioc['type'], ioc['threat_family'], 
                     ioc['confidence'], ioc['source']))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"IOC update error: {e}")
    
    def check_file_iocs(self, file_path):
        """Check file against IOC database"""
        matches = []
        
        try:
            # Calculate file hashes
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            hashes = [
                md5_hash.hexdigest(),
                sha1_hash.hexdigest(),
                sha256_hash.hexdigest()
            ]
            
            # Check against database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for hash_value in hashes:
                cursor.execute('''
                    SELECT indicator, type, threat_family, confidence, source
                    FROM iocs WHERE indicator = ?
                ''', (hash_value,))
                
                for row in cursor.fetchall():
                    matches.append({
                        'indicator': row[0],
                        'type': row[1],
                        'threat_family': row[2],
                        'confidence': row[3],
                        'source': row[4]
                    })
            
            conn.close()
            
        except Exception as e:
            logger.error(f"IOC checking error: {e}")
        
        return matches

class ThreatAttributionEngine:
    """Threat actor attribution system"""
    
    def __init__(self):
        self.actor_profiles = self._load_actor_profiles()
        
    def _load_actor_profiles(self):
        """Load threat actor profiles"""
        return {
            'APT1': {
                'aliases': ['Comment Crew', 'PLA Unit 61398'],
                'ttps': ['spear_phishing', 'web_shells', 'credential_harvesting'],
                'malware_families': ['BACKSPACE', 'SEASALT', 'WEBC2'],
                'targets': ['government', 'defense', 'finance']
            },
            'Lazarus': {
                'aliases': ['Hidden Cobra', 'Guardians of Peace'],
                'ttps': ['watering_hole', 'supply_chain', 'destructive_attacks'],
                'malware_families': ['FALLCHILL', 'SHARPKNOT', 'KEYMARBLE'],
                'targets': ['finance', 'cryptocurrency', 'media']
            }
        }
    
    def attribute_threat(self, analysis_results):
        """Attempt to attribute threat to known actors"""
        attribution = {
            'likely_actor': 'unknown',
            'confidence': 0,
            'reasoning': [],
            'alternative_actors': []
        }
        
        try:
            threat_family = analysis_results.get('threat_family', 'unknown')
            
            # Simple attribution based on malware family
            for actor, profile in self.actor_profiles.items():
                if threat_family.lower() in [mf.lower() for mf in profile['malware_families']]:
                    attribution['likely_actor'] = actor
                    attribution['confidence'] = 0.7
                    attribution['reasoning'].append(f"Malware family '{threat_family}' associated with {actor}")
                    break
            
            # Additional attribution logic would go here
            
        except Exception as e:
            logger.error(f"Attribution error: {e}")
        
        return attribution