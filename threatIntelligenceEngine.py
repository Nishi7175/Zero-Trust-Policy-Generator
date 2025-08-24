#!/usr/bin/env python3
"""
ThreatIntelligenceEngine.py - Threat Intelligence Correlation Module
Correlates network logs with threat intelligence to identify security risks
"""

import re
from datetime import datetime
from typing import Dict, List, Set
from collections import defaultdict

class ThreatIntelligenceEngine:
    """Correlates network activity with threat intelligence indicators"""
    
    def __init__(self):
        self.threats = []
        self.threat_indicators = self._initialize_threat_indicators()
        self.threat_score = 0
        self.ioc_database = self._initialize_ioc_database()
        
    def _initialize_threat_indicators(self) -> List[Dict]:
        """Initialize threat detection patterns"""
        return [
            {
                'type': 'suspicious_ip_range',
                'pattern': re.compile(r'192\.168\.1\.([8-9][0-9]|1[0-9][0-9])'),
                'severity': 'medium',
                'description': 'Access from suspicious IP range',
                'mitigation': 'Block IP range and investigate source'
            },
            {
                'type': 'unusual_user_agent',
                'pattern': re.compile(r'user_agent:custom|user_agent:automated'),
                'severity': 'low',
                'description': 'Non-standard user agent detected',
                'mitigation': 'Monitor for automated tools and bot activity'
            },
            {
                'type': 'privilege_escalation',
                'pattern': re.compile(r'privilege_escalation:detected'),
                'severity': 'critical',
                'description': 'Privilege escalation attempt detected',
                'mitigation': 'Immediate account review and privilege reduction'
            },
            {
                'type': 'lateral_movement',
                'pattern': re.compile(r'lateral_movement:attempt'),
                'severity': 'high',
                'description': 'Lateral movement attempt identified',
                'mitigation': 'Implement network segmentation and monitoring'
            },
            {
                'type': 'data_exfiltration_risk',
                'pattern': re.compile(r'data_exfiltration_risk:(medium|high)'),
                'severity': 'high',
                'description': 'Potential data exfiltration activity',
                'mitigation': 'Enable DLP monitoring and restrict data access'
            },
            {
                'type': 'honeypot_interaction',
                'pattern': re.compile(r'honeypot_trigger:true'),
                'severity': 'critical',
                'description': 'Interaction with honeypot system detected',
                'mitigation': 'Quarantine user and initiate incident response'
            },
            {
                'type': 'brute_force_attack',
                'pattern': re.compile(r'attempt_count:[5-9]|attempt_count:\d{2,}'),
                'severity': 'high',
                'description': 'Multiple failed authentication attempts',
                'mitigation': 'Implement account lockout and rate limiting'
            },
            {
                'type': 'anomalous_behavior',
                'pattern': re.compile(r'anomaly_score:0\.[7-9]|anomaly_score:1\.0'),
                'severity': 'medium',
                'description': 'Highly anomalous user behavior detected',
                'mitigation': 'Enable enhanced behavioral monitoring'
            },
            {
                'type': 'off_hours_access',
                'pattern': re.compile(r'time_restriction:violated'),
                'severity': 'medium',
                'description': 'Access during restricted hours',
                'mitigation': 'Enforce time-based access controls'
            },
            {
                'type': 'high_bandwidth_usage',
                'pattern': re.compile(r'bandwidth_usage:high'),
                'severity': 'medium',
                'description': 'Unusual high bandwidth consumption',
                'mitigation': 'Monitor for data exfiltration attempts'
            }
        ]
    
    def _initialize_ioc_database(self) -> Dict:
        """Initialize indicators of compromise database"""
        return {
            'malicious_ips': [
                '192.168.1.99',
                '10.0.0.666',
                '172.16.255.254'
            ],
            'suspicious_domains': [
                'suspicious-domain.com',
                'malware-c2.net',
                'phishing-site.org'
            ],
            'known_attack_signatures': [
                'SQL injection attempt',
                'XSS payload detected',
                'Command injection pattern'
            ],
            'malware_hashes': [
                'a1b2c3d4e5f6',
                'deadbeefcafe',
                '1234567890ab'
            ]
        }
    
    def correlate_threats(self, analysis_data: Dict) -> List[Dict]:
        """Correlate parsed logs with threat intelligence"""
        parsed_logs = analysis_data.get('parsed_logs', [])
        self.threats = []
        
        print(f"[INFO] Correlating {len(parsed_logs)} log entries with threat intelligence...")
        
        for log_entry in parsed_logs:
            log_string = self._serialize_log_entry(log_entry)
            threats_found = self._check_threat_indicators(log_entry, log_string)
            
            for threat in threats_found:
                self.threats.append(threat)
        
        # Remove duplicate threats and calculate overall threat score
        self._deduplicate_threats()
        self._calculate_threat_score()
        
        print(f"[INFO] Identified {len(self.threats)} unique threats")
        return self.threats
    
    def _serialize_log_entry(self, log_entry: Dict) -> str:
        """Convert log entry to searchable string"""
        return ' '.join([f"{k}:{v}" for k, v in log_entry.items()])
    
    def _check_threat_indicators(self, log_entry: Dict, log_string: str) -> List[Dict]:
        """Check log entry against all threat indicators"""
        threats_found = []
        
        for indicator in self.threat_indicators:
            if indicator['pattern'].search(log_string):
                threat = {
                    'type': indicator['type'],
                    'severity': indicator['severity'],
                    'description': indicator['description'],
                    'mitigation': indicator['mitigation'],
                    'user': log_entry.get('user', '').replace('user:', ''),
                    'resource': log_entry.get('resource', ''),
                    'timestamp': log_entry.get('timestamp', ''),
                    'source_ip': log_entry.get('ip', ''),
                    'details': self._extract_threat_details(log_entry, indicator),
                    'confidence': self._calculate_threat_confidence(log_entry, indicator),
                    'first_seen': datetime.now().isoformat(),
                    'occurrence_count': 1
                }
                threats_found.append(threat)
        
        # Check against IoC database
        ioc_threats = self._check_ioc_database(log_entry)
        threats_found.extend(ioc_threats)
        
        return threats_found
    
    def _extract_threat_details(self, log_entry: Dict, indicator: Dict) -> Dict:
        """Extract specific details for threat type"""
        details = {}
        
        threat_type = indicator['type']
        
        if threat_type == 'privilege_escalation':
            details['escalation_method'] = log_entry.get('method', 'unknown')
            details['target_privilege'] = log_entry.get('target_privilege', 'unknown')
            
        elif threat_type == 'lateral_movement':
            details['source_system'] = log_entry.get('source_system', 'unknown')
            details['target_system'] = log_entry.get('target_system', 'unknown')
            details['movement_technique'] = log_entry.get('technique', 'unknown')
            
        elif threat_type == 'data_exfiltration_risk':
            details['data_volume'] = log_entry.get('data_volume', 'unknown')
            details['destination'] = log_entry.get('dest_ip', 'unknown')
            details['exfiltration_method'] = log_entry.get('method', 'unknown')
            
        elif threat_type == 'brute_force_attack':
            details['attempt_count'] = log_entry.get('attempt_count', 'unknown')
            details['target_account'] = log_entry.get('user', 'unknown')
            details['attack_duration'] = log_entry.get('duration', 'unknown')
            
        elif threat_type == 'honeypot_interaction':
            details['honeypot_type'] = log_entry.get('honeypot_type', 'unknown')
            details['interaction_level'] = log_entry.get('interaction_level', 'unknown')
            
        return details
    
    def _calculate_threat_confidence(self, log_entry: Dict, indicator: Dict) -> float:
        """Calculate confidence score for threat detection"""
        base_confidence = 0.7
        
        # Increase confidence based on additional evidence
        if log_entry.get('success') == 'false':
            base_confidence += 0.1  # Failed attempts are suspicious
            
        if log_entry.get('mfa') == 'false':
            base_confidence += 0.1  # No MFA increases risk
            
        if log_entry.get('sensitivity') in ['high', 'critical']:
            base_confidence += 0.1  # Targeting sensitive resources
            
        # Decrease confidence for common, less severe indicators
        if indicator['severity'] == 'low':
            base_confidence -= 0.2
            
        return min(1.0, max(0.1, base_confidence))
    
    def _check_ioc_database(self, log_entry: Dict) -> List[Dict]:
        """Check log entry against IoC database"""
        ioc_threats = []
        
        source_ip = log_entry.get('ip', '')
        user_agent = log_entry.get('user_agent', '')
        resource = log_entry.get('resource', '')
        
        # Check malicious IPs
        if source_ip in self.ioc_database['malicious_ips']:
            threat = {
                'type': 'malicious_ip',
                'severity': 'high',
                'description': f'Access from known malicious IP: {source_ip}',
                'mitigation': 'Block IP immediately and investigate compromise',
                'user': log_entry.get('user', '').replace('user:', ''),
                'resource': resource,
                'timestamp': log_entry.get('timestamp', ''),
                'source_ip': source_ip,
                'details': {'ioc_type': 'malicious_ip', 'indicator': source_ip},
                'confidence': 0.9,
                'first_seen': datetime.now().isoformat(),
                'occurrence_count': 1
            }
            ioc_threats.append(threat)
        
        # Check suspicious domains in resource paths
        for domain in self.ioc_database['suspicious_domains']:
            if domain in resource:
                threat = {
                    'type': 'suspicious_domain',
                    'severity': 'medium',
                    'description': f'Access to suspicious domain: {domain}',
                    'mitigation': 'Block domain and scan for malware',
                    'user': log_entry.get('user', '').replace('user:', ''),
                    'resource': resource,
                    'timestamp': log_entry.get('timestamp', ''),
                    'source_ip': source_ip,
                    'details': {'ioc_type': 'suspicious_domain', 'indicator': domain},
                    'confidence': 0.8,
                    'first_seen': datetime.now().isoformat(),
                    'occurrence_count': 1
                }
                ioc_threats.append(threat)
        
        return ioc_threats
    
    def _deduplicate_threats(self) -> None:
        """Remove duplicate threats and merge occurrence counts"""
        threat_map = {}
        
        for threat in self.threats:
            # Create unique key for threat
            key = f"{threat['type']}_{threat['user']}_{threat['source_ip']}"
            
            if key in threat_map:
                # Merge with existing threat
                threat_map[key]['occurrence_count'] += 1
                threat_map[key]['confidence'] = max(
                    threat_map[key]['confidence'],
                    threat['confidence']
                )
            else:
                threat_map[key] = threat
        
        self.threats = list(threat_map.values())
    
    def _calculate_threat_score(self) -> None:
        """Calculate overall threat score for the environment"""
        if not self.threats:
            self.threat_score = 0
            return
        
        severity_weights = {
            'critical': 100,
            'high': 50,
            'medium': 25,
            'low': 10
        }
        
        total_score = 0
        for threat in self.threats:
            severity = threat['severity']
            confidence = threat['confidence']
            occurrences = threat['occurrence_count']
            
            threat_value = severity_weights.get(severity, 10) * confidence * min(occurrences, 5)
            total_score += threat_value
        
        # Normalize score to 0-100 range
        max_possible_score = len(self.threats) * 100 * 5  # Max severity * max occurrences
        self.threat_score = min(100, int((total_score / max_possible_score) * 100)) if max_possible_score > 0 else 0
    
    def get_threats(self) -> List[Dict]:
        """Get all identified threats"""
        return self.threats
    
    def get_threat_score(self) -> int:
        """Get overall threat score"""
        return self.threat_score
    
    def get_threats_by_severity(self, severity: str) -> List[Dict]:
        """Get threats filtered by severity level"""
        return [threat for threat in self.threats if threat['severity'] == severity]
    
    def get_threats_by_user(self, username: str) -> List[Dict]:
        """Get threats associated with specific user"""
        return [threat for threat in self.threats if threat['user'] == username]
    
    def get_critical_threats(self) -> List[Dict]:
        """Get all critical and high severity threats"""
        return [
            threat for threat in self.threats 
            if threat['severity'] in ['critical', 'high']
        ]
    
    def get_threat_summary(self) -> Dict:
        """Get summary statistics of identified threats"""
        if not self.threats:
            return {
                'total_threats': 0,
                'threat_score': 0,
                'severity_breakdown': {},
                'top_threat_types': [],
                'affected_users': 0
            }
        
        # Count by severity
        severity_counts = defaultdict(int)
        for threat in self.threats:
            severity_counts[threat['severity']] += 1
        
        # Count by type
        type_counts = defaultdict(int)
        for threat in self.threats:
            type_counts[threat['type']] += threat['occurrence_count']
        
        # Top threat types
        top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Count affected users
        affected_users = len(set(threat['user'] for threat in self.threats if threat['user']))
        
        return {
            'total_threats': len(self.threats),
            'threat_score': self.threat_score,
            'severity_breakdown': dict(severity_counts),
            'top_threat_types': [
                {'type': threat_type, 'count': count} 
                for threat_type, count in top_types
            ],
            'affected_users': affected_users,
            'critical_threats': len(self.get_critical_threats()),
            'unique_threat_types': len(type_counts)
        }
    
    def add_custom_indicator(self, threat_type: str, pattern: str, severity: str, 
                           description: str, mitigation: str) -> bool:
        """Add custom threat indicator"""
        try:
            compiled_pattern = re.compile(pattern)
            
            custom_indicator = {
                'type': threat_type,
                'pattern': compiled_pattern,
                'severity': severity,
                'description': description,
                'mitigation': mitigation
            }
            
            self.threat_indicators.append(custom_indicator)
            print(f"[INFO] Added custom threat indicator: {threat_type}")
            return True
            
        except re.error as e:
            print(f"[ERROR] Invalid regex pattern: {e}")
            return False
    
    def update_ioc_database(self, ioc_type: str, indicators: List[str]) -> None:
        """Update IoC database with new indicators"""
        if ioc_type in self.ioc_database:
            self.ioc_database[ioc_type].extend(indicators)
            print(f"[INFO] Updated {ioc_type} with {len(indicators)} new indicators")
        else:
            self.ioc_database[ioc_type] = indicators
            print(f"[INFO] Created new IoC category: {ioc_type}")
    
    def export_threats(self, filename: str = None) -> str:
        """Export threat intelligence results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_intelligence_{timestamp}.json"
        
        import json
        
        export_data = {
            'analysis_timestamp': datetime.now().isoformat(),
            'threat_score': self.threat_score,
            'summary': self.get_threat_summary(),
            'threats': self.threats,
            'threat_indicators_used': len(self.threat_indicators),
            'ioc_database_size': {
                category: len(indicators) 
                for category, indicators in self.ioc_database.items()
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f"[SUCCESS] Threat intelligence exported to {filename}")
            return filename
        except Exception as e:
            print(f"[ERROR] Failed to export threats: {str(e)}")
            return None
    
    def generate_threat_report(self) -> str:
        """Generate human-readable threat report"""
        if not self.threats:
            return "No threats identified in the analyzed logs."
        
        report = []
        report.append("=" * 60)
        report.append("THREAT INTELLIGENCE REPORT")
        report.append("=" * 60)
        report.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Overall Threat Score: {self.threat_score}/100")
        report.append("")
        
        summary = self.get_threat_summary()
        report.append("THREAT SUMMARY:")
        report.append(f"  Total Threats Identified: {summary['total_threats']}")
        report.append(f"  Affected Users: {summary['affected_users']}")
        report.append(f"  Critical/High Threats: {summary['critical_threats']}")
        report.append("")
        
        report.append("SEVERITY BREAKDOWN:")
        for severity, count in summary['severity_breakdown'].items():
            report.append(f"  {severity.capitalize()}: {count}")
        report.append("")
        
        report.append("TOP THREAT TYPES:")
        for threat_info in summary['top_threat_types']:
            report.append(f"  {threat_info['type']}: {threat_info['count']} occurrences")
        report.append("")
        
        # Critical threats details
        critical_threats = self.get_critical_threats()
        if critical_threats:
            report.append("CRITICAL THREATS REQUIRING IMMEDIATE ATTENTION:")
            for i, threat in enumerate(critical_threats[:5], 1):
                report.append(f"  {i}. {threat['description']}")
                report.append(f"     User: {threat['user']}")
                report.append(f"     Mitigation: {threat['mitigation']}")
                report.append("")
        
        return "\n".join(report)
