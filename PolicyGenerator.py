#!/usr/bin/env python3
"""
PolicyGenerator.py - Zero Trust Policy Generation Module
Generates security policies based on trust analysis and threat intelligence
"""

from datetime import datetime, timedelta
from typing import Dict, List
import uuid

class PolicyGenerator:
    """Generates zero trust security policies based on analysis data"""
    
    def __init__(self):
        self.policies = []
        self.policy_templates = self._initialize_policy_templates()
        self.risk_thresholds = {
            'critical': 0.8,
            'high': 0.6,
            'medium': 0.4,
            'low': 0.0
        }
    
    def _initialize_policy_templates(self) -> Dict:
        """Initialize policy templates for different scenarios"""
        return {
            'least_privilege': {
                'name': 'Least Privilege Access Control',
                'description': 'Restrict user access to minimum required resources',
                'conditions': [
                    'User trust score below threshold',
                    'Excessive resource access detected',
                    'Behavioral anomalies identified'
                ],
                'actions': [
                    'Review and reduce resource permissions',
                    'Implement just-in-time access',
                    'Enable enhanced monitoring'
                ]
            },
            'behavioral_monitoring': {
                'name': 'Enhanced Behavioral Monitoring',
                'description': 'Continuous monitoring for users with anomalous behavior',
                'conditions': [
                    'Behavioral risk score above threshold',
                    'Multiple failed authentication attempts',
                    'Unusual access patterns detected'
                ],
                'actions': [
                    'Enable real-time behavioral analysis',
                    'Require additional authentication factors',
                    'Generate security alerts for anomalous activity'
                ]
            },
            'geographic_restriction': {
                'name': 'Geographic Access Restriction',
                'description': 'Restrict access based on geographic location',
                'conditions': [
                    'Access from multiple geographic locations',
                    'Access from high-risk countries',
                    'Impossible travel scenarios detected'
                ],
                'actions': [
                    'Implement geo-fencing policies',
                    'Block access from unauthorized locations',
                    'Require location verification'
                ]
            },
            'temporal_restriction': {
                'name': 'Time-based Access Control',
                'description': 'Restrict access based on time patterns',
                'conditions': [
                    'Frequent off-hours access',
                    'Access during non-business hours',
                    'Irregular time patterns'
                ],
                'actions': [
                    'Implement time-based access windows',
                    'Require approval for off-hours access',
                    'Enable enhanced logging during restricted hours'
                ]
            },
            'network_segmentation': {
                'name': 'Network Micro-segmentation',
                'description': 'Isolate critical resources using network segmentation',
                'conditions': [
                    'High-value assets accessed',
                    'Lateral movement risk identified',
                    'Critical resource classification'
                ],
                'actions': [
                    'Deploy network access control (NAC)',
                    'Create isolated network segments',
                    'Implement encrypted communications'
                ]
            }
        }
    
    def create_policies(self, analysis_data: Dict, trust_data: List[Dict], 
                       threat_data: List[Dict], topology_data: Dict) -> List[Dict]:
        """Create comprehensive zero trust policies based on all analysis data"""
        self.policies = []
        
        print("[INFO] Generating zero trust policies...")
        
        # Generate user-specific policies based on trust relationships
        self._generate_user_policies(trust_data, analysis_data)
        
        # Generate threat-responsive policies
        self._generate_threat_policies(threat_data, analysis_data)
        
        # Generate network topology-based policies
        self._generate_network_policies(topology_data, analysis_data)
        
        # Generate resource-based policies
        self._generate_resource_policies(analysis_data)
        
        print(f"[SUCCESS] Generated {len(self.policies)} security policies")
        return self.policies
    
    def _generate_user_policies(self, trust_data: List[Dict], analysis_data: Dict) -> None:
        """Generate policies for individual users based on trust analysis"""
        for trust_rel in trust_data:
            user = trust_rel['user']
            trust_score = trust_rel['trust_score']
            trust_level = trust_rel['trust_level']
            risk_factors = trust_rel['risk_factors']
            
            # Generate least privilege policy for low trust users
            if trust_level == 'low' or trust_score < 0.4:
                policy = self._create_least_privilege_policy(user, trust_rel)
                self.policies.append(policy)
            
            # Generate behavioral monitoring policy
            if trust_rel['behavioral_score'] > 0.5:
                policy = self._create_behavioral_monitoring_policy(user, trust_rel)
                self.policies.append(policy)
            
            # Generate geographic restriction policy
            if 'Multiple geographic locations' in risk_factors:
                policy = self._create_geographic_policy(user, trust_rel)
                self.policies.append(policy)
            
            # Generate temporal restriction policy
            if 'Frequent off-hours access' in risk_factors:
                policy = self._create_temporal_policy(user, trust_rel)
                self.policies.append(policy)
    
    def _create_least_privilege_policy(self, user: str, trust_rel: Dict) -> Dict:
        """Create least privilege access policy for a user"""
        template = self.policy_templates['least_privilege']
        
        policy = {
            'id': str(uuid.uuid4()),
            'type': 'least_privilege',
            'target_type': 'user',
            'target': user,
            'title': f"Least Privilege Policy - {user}",
            'description': f"Restrict access for user {user} due to low trust score ({trust_rel['trust_score']:.2f})",
            'risk_level': self._determine_policy_risk_level(trust_rel['trust_score']),
            'conditions': [
                f"User trust score: {trust_rel['trust_score']:.2f}",
                f"Resource access count: {trust_rel['resource_count']}",
                f"Failure rate: {trust_rel['failure_rate']:.2f}"
            ],
            'actions': [
                "Review and reduce resource permissions to minimum required",
                "Implement just-in-time (JIT) access provisioning",
                "Require manager approval for sensitive resource access",
                "Enable enhanced session monitoring and recording"
            ],
            'priority': 'high' if trust_rel['trust_level'] == 'low' else 'medium',
            'status': 'pending',
            'created_timestamp': datetime.now().isoformat(),
            'effective_date': datetime.now().isoformat(),
            'review_date': (datetime.now() + timedelta(days=30)).isoformat(),
            'confidence_score': trust_rel['confidence'],
            'affected_resources': trust_rel.get('resource_count', 0),
            'compliance_frameworks': ['NIST Zero Trust', 'ISO 27001']
        }
        
        return policy
    
    def _create_behavioral_monitoring_policy(self, user: str, trust_rel: Dict) -> Dict:
        """Create behavioral monitoring policy for a user"""
        policy = {
            'id': str(uuid.uuid4()),
            'type': 'behavioral_monitoring',
            'target_type': 'user',
            'target': user,
            'title': f"Enhanced Behavioral Monitoring - {user}",
            'description': f"Continuous monitoring for {user} due to behavioral anomalies",
            'risk_level': 'high',
            'conditions': [
                f"Behavioral risk score: {trust_rel['behavioral_score']:.2f}",
                "Anomalous access patterns detected",
                "Requires continuous monitoring"
            ],
            'actions': [
                "Enable real-time user behavior analytics (UBA)",
                "Implement anomaly detection algorithms",
                "Generate immediate alerts for unusual activity",
                "Require periodic re-authentication",
                "Log all user activities with detailed metadata"
            ],
            'priority': 'high',
            'status': 'pending',
            'created_timestamp': datetime.now().isoformat(),
            'effective_date': datetime.now().isoformat(),
            'review_date': (datetime.now() + timedelta(days=14)).isoformat(),
            'confidence_score': trust_rel['confidence'],
            'monitoring_duration': '30 days',
            'alert_threshold': 0.7,
            'compliance_frameworks': ['NIST Zero Trust']
        }
        
        return policy
    
    def _create_geographic_policy(self, user: str, trust_rel: Dict) -> Dict:
        """Create geographic restriction policy for a user"""
        locations = trust_rel.get('geographic_locations', [])
        
        policy = {
            'id': str(uuid.uuid4()),
            'type': 'geographic_restriction',
            'target_type': 'user',
            'target': user,
            'title': f"Geographic Access Control - {user}",
            'description': f"Location-based access restrictions for {user}",
            'risk_level': 'medium',
            'conditions': [
                f"Access from {len(locations)} different locations: {', '.join(locations)}",
                "Multiple geographic locations detected",
                "Potential impossible travel scenarios"
            ],
            'actions': [
                "Implement geo-fencing based on approved locations",
                "Block access from unauthorized geographic regions",
                "Require additional verification for new locations",
                "Monitor for impossible travel patterns",
                "Maintain whitelist of approved countries/regions"
            ],
            'priority': 'medium',
            'status': 'pending',
            'created_timestamp': datetime.now().isoformat(),
            'effective_date': datetime.now().isoformat(),
            'review_date': (datetime.now() + timedelta(days=60)).isoformat(),
            'confidence_score': trust_rel['confidence'],
            'approved_locations': locations[:2] if locations else ['Unknown'],
            'blocked_regions': ['High-risk countries', 'Tor exit nodes'],
            'compliance_frameworks': ['GDPR', 'SOX']
        }
        
        return policy
    
    def _create_temporal_policy(self, user: str, trust_rel: Dict) -> Dict:
        """Create temporal restriction policy for a user"""
        policy = {
            'id': str(uuid.uuid4()),
            'type': 'temporal_restriction',
            'target_type': 'user',
            'target': user,
            'title': f"Time-based Access Control - {user}",
            'description': f"Temporal access restrictions for {user} due to off-hours activity",
            'risk_level': 'medium',
            'conditions': [
                "Frequent off-hours access detected",
                "Access during non-business hours",
                "Irregular temporal patterns identified"
            ],
            'actions': [
                "Restrict access to business hours (9 AM - 6 PM)",
                "Require manager approval for off-hours access",
                "Implement time-based conditional access",
                "Enable enhanced logging during restricted hours",
                "Send alerts for off-hours access attempts"
            ],
            'priority': 'medium',
            'status': 'pending',
            'created_timestamp': datetime.now().isoformat(),
            'effective_date': datetime.now().isoformat(),
            'review_date': (datetime.now() + timedelta(days=45)).isoformat(),
            'confidence_score': trust_rel['confidence'],
            'business_hours': '09:00-18:00',
            'timezone': 'UTC',
            'emergency_override': True,
            'compliance_frameworks': ['SOX', 'PCI DSS']
        }
        
        return policy
    
    def _generate_threat_policies(self, threat_data: List[Dict], analysis_data: Dict) -> None:
        """Generate policies based on threat intelligence"""
        for threat in threat_data:
            if threat.get('severity') in ['critical', 'high']:
                policy = self._create_threat_response_policy(threat)
                self.policies.append(policy)
    
    def _create_threat_response_policy(self, threat: Dict) -> Dict:
        """Create threat response policy"""
        policy = {
            'id': str(uuid.uuid4()),
            'type': 'threat_response',
            'target_type': 'threat',
            'target': threat.get('type', 'unknown_threat'),
            'title': f"Threat Response - {threat.get('type', 'Unknown')}",
            'description': f"Automated response to {threat.get('severity', 'unknown')} severity threat",
            'risk_level': threat.get('severity', 'medium'),
            'conditions': [
                f"Threat type: {threat.get('type', 'unknown')}",
                f"Severity: {threat.get('severity', 'unknown')}",
                f"Affected user: {threat.get('user', 'unknown')}"
            ],
            'actions': [
                threat.get('mitigation', 'Generic security review required'),
                "Enable enhanced monitoring for affected user",
                "Generate immediate security alert",
                "Initiate incident response if critical"
            ],
            'priority': 'critical' if threat.get('severity') == 'critical' else 'high',
            'status': 'active',
            'created_timestamp': datetime.now().isoformat(),
            'effective_date': datetime.now().isoformat(),
            'review_date': (datetime.now() + timedelta(days=7)).isoformat(),
            'threat_details': threat,
            'compliance_frameworks': ['NIST Cybersecurity Framework']
        }
        
        return policy
    
    def _generate_network_policies(self, topology_data: Dict, analysis_data: Dict) -> None:
        """Generate network segmentation policies based on topology analysis"""
        isolation_candidates = topology_data.get('isolation_candidates', [])
        
        for candidate in isolation_candidates:
            if candidate.get('criticality', 0) >= 0.7:
                policy = self._create_network_segmentation_policy(candidate)
                self.policies.append(policy)
    
    def _create_network_segmentation_policy(self, candidate: Dict) -> Dict:
        """Create network segmentation policy"""
        policy = {
            'id': str(uuid.uuid4()),
            'type': 'network_segmentation',
            'target_type': 'resource',
            'target': candidate.get('node', 'unknown_resource'),
            'title': f"Network Segmentation - {candidate.get('node', 'Resource')}",
            'description': f"Micro-segmentation for critical asset with criticality score {candidate.get('criticality', 0):.2f}",
            'risk_level': 'high' if candidate.get('criticality', 0) >= 0.8 else 'medium',
            'conditions': [
                f"Asset criticality: {candidate.get('criticality', 0):.2f}",
                f"Network connections: {candidate.get('connections', 0)}",
                "Critical asset requires isolation"
            ],
            'actions': [
                "Deploy network access control (NAC) solution",
                "Create dedicated network segment/VLAN",
                "Implement default-deny firewall rules",
                "Enable encrypted communications (TLS/IPSec)",
                "Deploy intrusion detection/prevention systems"
            ],
            'priority': 'high',
            'status': 'pending',
            'created_timestamp': datetime.now().isoformat(),
            'effective_date': (datetime.now() + timedelta(days=7)).isoformat(),
            'review_date': (datetime.now() + timedelta(days=90)).isoformat(),
            'implementation_complexity': 'medium',
            'estimated_downtime': '2-4 hours',
            'compliance_frameworks': ['NIST Zero Trust', 'ISO 27001']
        }
        
        return policy
    
    def _generate_resource_policies(self, analysis_data: Dict) -> None:
        """Generate policies for high-sensitivity resources"""
        high_sensitivity_access = analysis_data.get('high_sensitivity_access', [])
        
        # Group by resource
        resource_access = {}
        for access in high_sensitivity_access:
            resource = access['resource']
            if resource not in resource_access:
                resource_access[resource] = []
            resource_access[resource].append(access)
        
        # Create policies for resources with multiple high-sensitivity accesses
        for resource, accesses in resource_access.items():
            if len(accesses) > 1:  # Multiple users accessing sensitive resource
                policy = self._create_resource_protection_policy(resource, accesses)
                self.policies.append(policy)
    
    def _create_resource_protection_policy(self, resource: str, accesses: List[Dict]) -> Dict:
        """Create resource protection policy"""
        users = list(set(access['user'] for access in accesses))
        
        policy = {
            'id': str(uuid.uuid4()),
            'type': 'resource_protection',
            'target_type': 'resource',
            'target': resource,
            'title': f"Enhanced Protection - {resource}",
            'description': f"Additional security controls for high-sensitivity resource",
            'risk_level': 'high',
            'conditions': [
                f"High-sensitivity resource: {resource}",
                f"Accessed by {len(users)} users",
                "Requires enhanced protection"
            ],
            'actions': [
                "Implement privileged access management (PAM)",
                "Enable data loss prevention (DLP) monitoring",
                "Require dual authorization for access",
                "Enable detailed audit logging",
                "Implement data encryption at rest and in transit"
            ],
            'priority': 'high',
            'status': 'pending',
            'created_timestamp': datetime.now().isoformat(),
            'effective_date': (datetime.now() + timedelta(days=3)).isoformat(),
            'review_date': (datetime.now() + timedelta(days=30)).isoformat(),
            'affected_users': users,
            'data_classification': 'sensitive',
            'compliance_frameworks': ['GDPR', 'HIPAA', 'PCI DSS']
        }
        
        return policy
    
    def _determine_policy_risk_level(self, trust_score: float) -> str:
        """Determine policy risk level based on trust score"""
        if trust_score <= self.risk_thresholds['low']:
            return 'critical'
        elif trust_score <= self.risk_thresholds['medium']:
            return 'high'
        elif trust_score <= self.risk_thresholds['high']:
            return 'medium'
        else:
            return 'low'
    
    def get_policies_by_type(self, policy_type: str) -> List[Dict]:
        """Get policies filtered by type"""
        return [policy for policy in self.policies if policy['type'] == policy_type]
    
    def get_policies_by_priority(self, priority: str) -> List[Dict]:
        """Get policies filtered by priority"""
        return [policy for policy in self.policies if policy['priority'] == priority]
    
    def get_policy_summary(self) -> Dict:
        """Get summary statistics of generated policies"""
        if not self.policies:
            return {}
        
        total_policies = len(self.policies)
        
        # Count by type
        type_counts = {}
        for policy in self.policies:
            policy_type = policy['type']
            type_counts[policy_type] = type_counts.get(policy_type, 0) + 1
        
        # Count by priority
        priority_counts = {}
        for policy in self.policies:
            priority = policy['priority']
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
        
        # Count by risk level
        risk_counts = {}
        for policy in self.policies:
            risk_level = policy['risk_level']
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        return {
            'total_policies': total_policies,
            'policies_by_type': type_counts,
            'policies_by_priority': priority_counts,
            'policies_by_risk_level': risk_counts,
            'pending_policies': len([p for p in self.policies if p['status'] == 'pending']),
            'active_policies': len([p for p in self.policies if p['status'] == 'active'])
        }
