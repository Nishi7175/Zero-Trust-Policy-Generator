#!/usr/bin/env python3
"""
TrustRelationshipManager.py - Trust Relationship Analysis Module
Generates and manages user trust relationships based on behavioral patterns
"""

from datetime import datetime
from typing import Dict, List, Tuple
import math

class TrustRelationshipManager:
    """Manages trust relationships and behavioral analysis for users"""
    
    def __init__(self):
        self.trust_relationships = []
        self.trust_thresholds = {
            'high': 0.7,
            'medium': 0.4,
            'low': 0.0
        }
        self.behavioral_weights = {
            'resource_access': 0.25,
            'failure_rate': 0.20,
            'risk_score': 0.30,
            'geographic_anomaly': 0.15,
            'temporal_anomaly': 0.10
        }
    
    def generate_trust_matrix(self, analysis_data: Dict) -> List[Dict]:
        """Generate trust relationships for all users based on analysis data"""
        access_patterns = analysis_data.get('access_patterns', {})
        failed_accesses = analysis_data.get('failed_accesses', [])
        high_sensitivity_access = analysis_data.get('high_sensitivity_access', [])
        
        self.trust_relationships = []
        
        print(f"[INFO] Generating trust matrix for {len(access_patterns)} users...")
        
        for username, pattern in access_patterns.items():
            trust_relationship = self._calculate_user_trust(
                username, pattern, failed_accesses, high_sensitivity_access
            )
            self.trust_relationships.append(trust_relationship)
        
        # Sort by trust score (lowest first - highest risk)
        self.trust_relationships.sort(key=lambda x: x['trust_score'])
        
        print(f"[INFO] Generated {len(self.trust_relationships)} trust relationships")
        return self.trust_relationships
    
    def _calculate_user_trust(self, username: str, pattern: Dict, 
                            failed_accesses: List, high_sensitivity_access: List) -> Dict:
        """Calculate trust relationship for a single user"""
        
        # Base trust metrics
        resource_count = len(pattern.get('resources', []))
        action_count = len(pattern.get('actions', []))
        failure_count = pattern.get('failures', 0)
        base_risk_score = pattern.get('risk_score', 0.0)
        
        # Calculate individual risk factors
        resource_risk = self._calculate_resource_risk(resource_count)
        failure_risk = self._calculate_failure_risk(failure_count, action_count)
        behavioral_risk = min(base_risk_score, 1.0)
        geographic_risk = self._calculate_geographic_risk(pattern)
        temporal_risk = self._calculate_temporal_risk(pattern)
        
        # Weighted trust score calculation
        trust_score = 1.0 - (
            resource_risk * self.behavioral_weights['resource_access'] +
            failure_risk * self.behavioral_weights['failure_rate'] +
            behavioral_risk * self.behavioral_weights['risk_score'] +
            geographic_risk * self.behavioral_weights['geographic_anomaly'] +
            temporal_risk * self.behavioral_weights['temporal_anomaly']
        )
        
        # Ensure trust score is between 0 and 1
        trust_score = max(0.0, min(1.0, trust_score))
        
        # Determine trust level
        trust_level = self._determine_trust_level(trust_score)
        
        # Identify risk factors
        risk_factors = self._identify_risk_factors(
            username, pattern, resource_count, failure_count, 
            failed_accesses, high_sensitivity_access
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(trust_level, risk_factors, pattern)
        
        # Calculate confidence score
        confidence = self._calculate_confidence(pattern, action_count)
        
        trust_relationship = {
            'user': username,
            'trust_score': round(trust_score, 3),
            'trust_level': trust_level,
            'confidence': round(confidence, 3),
            'resource_count': resource_count,
            'action_count': action_count,
            'failure_count': failure_count,
            'failure_rate': round(failure_count / max(action_count, 1), 3),
            'behavioral_score': round(base_risk_score, 3),
            'risk_factors': risk_factors,
            'recommendations': recommendations,
            'last_activity': pattern.get('last_activity'),
            'geographic_locations': pattern.get('geographic_locations', []),
            'device_fingerprints': pattern.get('device_fingerprints', []),
            'sensitivity_profile': dict(pattern.get('sensitivity_levels', {})),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        return trust_relationship
    
    def _calculate_resource_risk(self, resource_count: int) -> float:
        """Calculate risk based on number of resources accessed"""
        if resource_count <= 5:
            return 0.0
        elif resource_count <= 10:
            return 0.3
        elif resource_count <= 20:
            return 0.6
        else:
            return 1.0
    
    def _calculate_failure_risk(self, failure_count: int, total_actions: int) -> float:
        """Calculate risk based on authentication/access failure rate"""
        if total_actions == 0:
            return 0.0
        
        failure_rate = failure_count / total_actions
        
        if failure_rate <= 0.05:
            return 0.0
        elif failure_rate <= 0.15:
            return 0.4
        elif failure_rate <= 0.30:
            return 0.7
        else:
            return 1.0
    
    def _calculate_geographic_risk(self, pattern: Dict) -> float:
        """Calculate risk based on geographic access patterns"""
        locations = pattern.get('geographic_locations', [])
        location_count = len(locations)
        
        if location_count <= 1:
            return 0.0
        elif location_count == 2:
            return 0.3
        elif location_count <= 4:
            return 0.6
        else:
            return 1.0
    
    def _calculate_temporal_risk(self, pattern: Dict) -> float:
        """Calculate risk based on temporal access patterns"""
        access_times = pattern.get('access_times', [])
        
        if not access_times:
            return 0.0
        
        # Calculate access time variance (higher variance = more suspicious)
        if len(access_times) < 3:
            return 0.0
        
        # Check for unusual hour patterns (e.g., consistent off-hours access)
        off_hours_count = sum(1 for hour in access_times if hour < 6 or hour > 22)
        off_hours_ratio = off_hours_count / len(access_times)
        
        if off_hours_ratio <= 0.1:
            return 0.0
        elif off_hours_ratio <= 0.3:
            return 0.4
        else:
            return 0.8
    
    def _determine_trust_level(self, trust_score: float) -> str:
        """Determine categorical trust level from numerical score"""
        if trust_score >= self.trust_thresholds['high']:
            return 'high'
        elif trust_score >= self.trust_thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _identify_risk_factors(self, username: str, pattern: Dict, resource_count: int,
                             failure_count: int, failed_accesses: List, 
                             high_sensitivity_access: List) -> List[str]:
        """Identify specific risk factors for a user"""
        risk_factors = []
        
        # High resource access
        if resource_count > 15:
            risk_factors.append("Excessive resource access")
        
        # High failure rate
        action_count = len(pattern.get('actions', []))
        if failure_count > 0 and (failure_count / max(action_count, 1)) > 0.15:
            risk_factors.append("High authentication failure rate")
        
        # Behavioral anomalies
        if pattern.get('risk_score', 0) > 0.5:
            risk_factors.append("Behavioral anomalies detected")
        
        # Multiple geographic locations
        if len(pattern.get('geographic_locations', [])) > 2:
            risk_factors.append("Multiple geographic locations")
        
        # Multiple devices
        if len(pattern.get('device_fingerprints', [])) > 3:
            risk_factors.append("Multiple device fingerprints")
        
        # High sensitivity access
        user_sensitive_access = [
            access for access in high_sensitivity_access 
            if access['user'] == username
        ]
        if len(user_sensitive_access) > 0:
            risk_factors.append("Critical resource access")
        
        # Off-hours access pattern
        access_times = pattern.get('access_times', [])
        if access_times:
            off_hours_count = sum(1 for hour in access_times if hour < 6 or hour > 22)
            if off_hours_count / len(access_times) > 0.3:
                risk_factors.append("Frequent off-hours access")
        
        return risk_factors
    
    def _generate_recommendations(self, trust_level: str, risk_factors: List[str], 
                                pattern: Dict) -> List[str]:
        """Generate security recommendations based on trust level and risk factors"""
        recommendations = []
        
        # Base recommendations by trust level
        if trust_level == 'low':
            recommendations.extend([
                "Implement continuous authentication monitoring",
                "Require enhanced multi-factor authentication",
                "Enable privileged session recording",
                "Conduct immediate access review"
            ])
        elif trust_level == 'medium':
            recommendations.extend([
                "Review and validate current permissions",
                "Implement time-limited access tokens",
                "Enable behavioral monitoring"
            ])
        
        # Specific recommendations based on risk factors
        if "Excessive resource access" in risk_factors:
            recommendations.append("Conduct access review and remove unnecessary permissions")
        
        if "High authentication failure rate" in risk_factors:
            recommendations.append("Investigate authentication issues and potential compromise")
        
        if "Behavioral anomalies detected" in risk_factors:
            recommendations.append("Enable real-time behavioral analysis")
        
        if "Multiple geographic locations" in risk_factors:
            recommendations.append("Implement geo-fencing and location-based policies")
        
        if "Multiple device fingerprints" in risk_factors:
            recommendations.append("Enforce device registration and management")
        
        if "Critical resource access" in risk_factors:
            recommendations.append("Enable privileged access management (PAM)")
        
        if "Frequent off-hours access" in risk_factors:
            recommendations.append("Implement time-based access restrictions")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:6]  # Limit to top 6 recommendations
    
    def _calculate_confidence(self, pattern: Dict, action_count: int) -> float:
        """Calculate confidence score for trust assessment"""
        base_confidence = 0.5
        
        # More actions = higher confidence
        if action_count >= 50:
            base_confidence += 0.3
        elif action_count >= 20:
            base_confidence += 0.2
        elif action_count >= 10:
            base_confidence += 0.1
        
        # More diverse data points = higher confidence
        if pattern.get('geographic_locations'):
            base_confidence += 0.1
        
        if pattern.get('device_fingerprints'):
            base_confidence += 0.1
        
        if pattern.get('access_times'):
            base_confidence += 0.05
        
        # Ensure confidence is between 0 and 1
        return min(1.0, base_confidence)
    
    def get_trust_summary(self) -> Dict:
        """Get summary statistics of trust relationships"""
        if not self.trust_relationships:
            return {}
        
        trust_levels = {'high': 0, 'medium': 0, 'low': 0}
        total_users = len(self.trust_relationships)
        
        for relationship in self.trust_relationships:
            trust_levels[relationship['trust_level']] += 1
        
        avg_trust_score = sum(
            rel['trust_score'] for rel in self.trust_relationships
        ) / total_users
        
        high_risk_users = [
            rel for rel in self.trust_relationships 
            if rel['trust_level'] == 'low'
        ]
        
        return {
            'total_users': total_users,
            'trust_distribution': {
                level: {'count': count, 'percentage': round(count/total_users*100, 1)}
                for level, count in trust_levels.items()
            },
            'average_trust_score': round(avg_trust_score, 3),
            'high_risk_user_count': len(high_risk_users),
            'users_requiring_attention': len([
                rel for rel in self.trust_relationships
                if rel['trust_level'] in ['low', 'medium']
            ])
        }
    
    def get_user_trust(self, username: str) -> Dict:
        """Get trust relationship for specific user"""
        for relationship in self.trust_relationships:
            if relationship['user'] == username:
                return relationship
        return None
    
    def update_trust_thresholds(self, high_threshold: float = 0.7, 
                              medium_threshold: float = 0.4) -> None:
        """Update trust level thresholds"""
        self.trust_thresholds['high'] = high_threshold
        self.trust_thresholds['medium'] = medium_threshold
        
        # Recalculate trust levels for existing relationships
        for relationship in self.trust_relationships:
            relationship['trust_level'] = self._determine_trust_level(
                relationship['trust_score']
            )
    
    def export_trust_matrix(self, filename: str = None) -> str:
        """Export trust matrix to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"trust_matrix_{timestamp}.json"
        
        import json
        
        export_data = {
            'generation_timestamp': datetime.now().isoformat(),
            'trust_thresholds': self.trust_thresholds,
            'behavioral_weights': self.behavioral_weights,
            'summary': self.get_trust_summary(),
            'trust_relationships': self.trust_relationships
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f"[SUCCESS] Trust matrix exported to {filename}")
            return filename
        except Exception as e:
            print(f"[ERROR] Failed to export trust matrix: {str(e)}")
            return None
