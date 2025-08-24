#!/usr/bin/env python3
"""
LogAnalyzer.py - Network Log Analysis Module
Parses and analyzes Zeek/Bro network logs for user access patterns
"""

import re
from datetime import datetime
from typing import Dict, List, Set, Tuple
from collections import defaultdict

class LogAnalyzer:
    """Analyzes network logs to identify user access patterns and behaviors"""
    
    def __init__(self):
        self.raw_logs = []
        self.parsed_logs = []
        self.access_patterns = {}
        self.users = set()
        self.resources = set()
        self.failed_accesses = []
        self.high_sensitivity_access = []
        
    def load_logs(self, log_file_path: str) -> bool:
        """Load network logs from file"""
        try:
            with open(log_file_path, 'r') as file:
                self.raw_logs = file.readlines()
            
            print(f"[INFO] Loaded {len(self.raw_logs)} log entries")
            return len(self.raw_logs) > 0
            
        except FileNotFoundError:
            print(f"[ERROR] Log file not found: {log_file_path}")
            return False
        except Exception as e:
            print(f"[ERROR] Error loading logs: {str(e)}")
            return False
    
    def parse_log_entry(self, log_line: str) -> Dict:
        """Parse a single log entry from Zeek/Bro format"""
        log_entry = {}
        
        # Split by pipe separator
        parts = log_line.strip().split(' | ')
        
        for part in parts:
            if ':' in part:
                key, value = part.split(':', 1)
                log_entry[key.strip()] = value.strip()
        
        # Handle timestamp (first part without colon)
        if parts and ':' not in parts[0]:
            log_entry['timestamp'] = parts[0].strip()
        
        return log_entry
    
    def parse_logs(self) -> List[Dict]:
        """Parse all loaded logs"""
        self.parsed_logs = []
        
        for log_line in self.raw_logs:
            if log_line.strip():  # Skip empty lines
                parsed_entry = self.parse_log_entry(log_line)
                if parsed_entry:
                    self.parsed_logs.append(parsed_entry)
        
        print(f"[INFO] Parsed {len(self.parsed_logs)} log entries")
        return self.parsed_logs
    
    def analyze_access_patterns(self) -> Dict:
        """Analyze user access patterns from parsed logs"""
        if not self.parsed_logs:
            self.parse_logs()
        
        self.access_patterns = {}
        self.users = set()
        self.resources = set()
        self.failed_accesses = []
        self.high_sensitivity_access = []
        
        for log_entry in self.parsed_logs:
            user = log_entry.get('user', '').replace('user:', '')
            resource = log_entry.get('resource', '')
            action = log_entry.get('action', '')
            success = log_entry.get('success', 'true').lower() == 'true'
            sensitivity = log_entry.get('sensitivity', 'low')
            
            if not user or not resource:
                continue
            
            # Track users and resources
            self.users.add(user)
            self.resources.add(resource)
            
            # Initialize user pattern if not exists
            if user not in self.access_patterns:
                self.access_patterns[user] = {
                    'resources': set(),
                    'actions': [],
                    'failures': 0,
                    'sessions': [],
                    'risk_score': 0.0,
                    'last_activity': None,
                    'geographic_locations': set(),
                    'device_fingerprints': set(),
                    'access_times': [],
                    'sensitivity_levels': defaultdict(int)
                }
            
            pattern = self.access_patterns[user]
            
            # Update access pattern
            pattern['resources'].add(resource)
            pattern['actions'].append(action)
            pattern['sensitivity_levels'][sensitivity] += 1
            
            # Track failures
            if not success:
                pattern['failures'] += 1
                self.failed_accesses.append({
                    'user': user,
                    'resource': resource,
                    'action': action,
                    'timestamp': log_entry.get('timestamp', '')
                })
            
            # Track high sensitivity access
            if sensitivity in ['high', 'critical']:
                self.high_sensitivity_access.append({
                    'user': user,
                    'resource': resource,
                    'sensitivity': sensitivity,
                    'timestamp': log_entry.get('timestamp', '')
                })
            
            # Extract additional metadata
            if 'geo' in log_entry:
                pattern['geographic_locations'].add(log_entry['geo'])
            
            if 'device' in log_entry:
                pattern['device_fingerprints'].add(log_entry['device'])
            
            # Parse timestamp for temporal analysis
            timestamp = log_entry.get('timestamp', '')
            if timestamp:
                try:
                    dt = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                    pattern['access_times'].append(dt.hour)
                    pattern['last_activity'] = timestamp
                except ValueError:
                    pass  # Skip invalid timestamps
            
            # Calculate basic risk score
            risk_score = 0.0
            
            # Risk factors
            if log_entry.get('privilege_escalation') == 'detected':
                risk_score += 0.3
            
            if log_entry.get('lateral_movement') == 'attempt':
                risk_score += 0.4
            
            if log_entry.get('anomaly_score'):
                try:
                    risk_score += float(log_entry['anomaly_score']) * 0.2
                except ValueError:
                    pass
            
            if log_entry.get('behavioral_deviation'):
                try:
                    risk_score += float(log_entry['behavioral_deviation']) * 0.3
                except ValueError:
                    pass
            
            # Update user's maximum risk score
            pattern['risk_score'] = max(pattern['risk_score'], risk_score)
        
        # Convert sets to lists for JSON serialization
        for user, pattern in self.access_patterns.items():
            pattern['resources'] = list(pattern['resources'])
            pattern['geographic_locations'] = list(pattern['geographic_locations'])
            pattern['device_fingerprints'] = list(pattern['device_fingerprints'])
        
        print(f"[INFO] Analyzed {len(self.users)} users accessing {len(self.resources)} resources")
        print(f"[INFO] Identified {len(self.failed_accesses)} failed access attempts")
        print(f"[INFO] Found {len(self.high_sensitivity_access)} high-sensitivity accesses")
        
        return {
            'access_patterns': self.access_patterns,
            'users': list(self.users),
            'resources': list(self.resources),
            'failed_accesses': self.failed_accesses,
            'high_sensitivity_access': self.high_sensitivity_access,
            'parsed_logs': self.parsed_logs
        }
    
    def get_user_statistics(self, username: str) -> Dict:
        """Get detailed statistics for a specific user"""
        if username not in self.access_patterns:
            return None
        
        pattern = self.access_patterns[username]
        
        stats = {
            'username': username,
            'total_resources_accessed': len(pattern['resources']),
            'total_actions': len(pattern['actions']),
            'failure_rate': pattern['failures'] / max(len(pattern['actions']), 1),
            'risk_score': pattern['risk_score'],
            'unique_locations': len(pattern['geographic_locations']),
            'unique_devices': len(pattern['device_fingerprints']),
            'most_common_access_hour': self._get_most_common_hour(pattern['access_times']),
            'sensitivity_breakdown': dict(pattern['sensitivity_levels']),
            'last_activity': pattern['last_activity']
        }
        
        return stats
    
    def _get_most_common_hour(self, access_times: List[int]) -> int:
        """Find the most common access hour"""
        if not access_times:
            return None
        
        hour_counts = defaultdict(int)
        for hour in access_times:
            hour_counts[hour] += 1
        
        return max(hour_counts.items(), key=lambda x: x[1])[0] if hour_counts else None
    
    def identify_anomalous_users(self, threshold: float = 0.5) -> List[str]:
        """Identify users with anomalous behavior patterns"""
        anomalous_users = []
        
        for user, pattern in self.access_patterns.items():
            # Check various anomaly indicators
            is_anomalous = False
            
            # High risk score
            if pattern['risk_score'] > threshold:
                is_anomalous = True
            
            # Excessive resource access
            if len(pattern['resources']) > 15:
                is_anomalous = True
            
            # High failure rate
            failure_rate = pattern['failures'] / max(len(pattern['actions']), 1)
            if failure_rate > 0.2:
                is_anomalous = True
            
            # Multiple geographic locations
            if len(pattern['geographic_locations']) > 2:
                is_anomalous = True
            
            # Multiple devices
            if len(pattern['device_fingerprints']) > 3:
                is_anomalous = True
            
            if is_anomalous:
                anomalous_users.append(user)
        
        print(f"[INFO] Identified {len(anomalous_users)} anomalous users")
        return anomalous_users
    
    def generate_access_summary(self) -> Dict:
        """Generate a summary of access patterns"""
        if not self.access_patterns:
            return {}
        
        total_users = len(self.access_patterns)
        total_resources = len(self.resources)
        total_failed_access = len(self.failed_accesses)
        
        # Calculate average metrics
        avg_resources_per_user = sum(
            len(pattern['resources']) for pattern in self.access_patterns.values()
        ) / total_users
        
        avg_risk_score = sum(
            pattern['risk_score'] for pattern in self.access_patterns.values()
        ) / total_users
        
        # Find top resource accessors
        top_users = sorted(
            self.access_patterns.items(),
            key=lambda x: len(x[1]['resources']),
            reverse=True
        )[:5]
        
        summary = {
            'total_users': total_users,
            'total_resources': total_resources,
            'total_failed_accesses': total_failed_access,
            'average_resources_per_user': round(avg_resources_per_user, 2),
            'average_risk_score': round(avg_risk_score, 3),
            'top_resource_users': [
                {
                    'user': user,
                    'resource_count': len(pattern['resources']),
                    'risk_score': pattern['risk_score']
                }
                for user, pattern in top_users
            ],
            'high_sensitivity_access_count': len(self.high_sensitivity_access)
        }
        
        return summary
