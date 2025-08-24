#!/usr/bin/env python3
"""
Zero Trust Policy Generator - Main Application
Analyzes network logs and generates least-privilege policies
"""

import json
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Set
from LogAnalyzer import LogAnalyzer
from TrustRelationshipManager import TrustRelationshipManager
from PolicyGenerator import PolicyGenerator
from ThreatIntelligenceEngine import ThreatIntelligenceEngine
from NetworkTopologyMapper import NetworkTopologyMapper

class ZeroTrustPolicyGenerator:
    """Main class for Zero Trust Policy Generation"""
    
    def __init__(self):
        self.log_analyzer = LogAnalyzer()
        self.trust_manager = TrustRelationshipManager()
        self.policy_generator = PolicyGenerator()
        self.threat_engine = ThreatIntelligenceEngine()
        self.topology_mapper = NetworkTopologyMapper()
        
        self.analysis_results = {}
        self.trust_relationships = []
        self.generated_policies = []
        self.risk_metrics = {}
        
    def load_network_logs(self, log_file_path: str) -> bool:
        """Load and validate network logs from file"""
        try:
            print(f"[INFO] Loading network logs from {log_file_path}")
            return self.log_analyzer.load_logs(log_file_path)
        except Exception as e:
            print(f"[ERROR] Failed to load logs: {str(e)}")
            return False
    
    def analyze_logs(self) -> Dict:
        """Perform comprehensive log analysis"""
        print("[INFO] Starting network log analysis...")
        
        # Parse and analyze logs
        self.analysis_results = self.log_analyzer.analyze_access_patterns()
        
        # Generate trust relationships
        print("[INFO] Generating trust relationships...")
        self.trust_relationships = self.trust_manager.generate_trust_matrix(
            self.analysis_results
        )
        
        # Perform threat intelligence correlation
        print("[INFO] Correlating threat intelligence...")
        threat_indicators = self.threat_engine.correlate_threats(
            self.analysis_results
        )
        
        # Map network topology and risk paths
        print("[INFO] Mapping network topology...")
        topology_data = self.topology_mapper.map_topology(
            self.analysis_results
        )
        
        return {
            'access_patterns': self.analysis_results,
            'trust_relationships': self.trust_relationships,
            'threats': threat_indicators,
            'topology': topology_data
        }
    
    def generate_policies(self) -> List[Dict]:
        """Generate zero trust policies based on analysis"""
        print("[INFO] Generating zero trust policies...")
        
        self.generated_policies = self.policy_generator.create_policies(
            analysis_data=self.analysis_results,
            trust_data=self.trust_relationships,
            threat_data=self.threat_engine.get_threats(),
            topology_data=self.topology_mapper.get_topology()
        )
        
        return self.generated_policies
    
    def calculate_risk_metrics(self) -> Dict:
        """Calculate comprehensive risk metrics"""
        print("[INFO] Calculating risk metrics...")
        
        over_privileged = len([
            rel for rel in self.trust_relationships 
            if rel.get('trust_level') == 'low' or rel.get('resource_count', 0) > 10
        ])
        
        lateral_movement_risks = len(
            self.topology_mapper.get_risk_paths()
        )
        
        attack_surface = len(self.analysis_results.get('resources', []))
        
        behavioral_anomalies = len([
            rel for rel in self.trust_relationships
            if rel.get('behavioral_score', 0) > 0.5
        ])
        
        self.risk_metrics = {
            'over_privileged_users': over_privileged,
            'lateral_movement_risks': lateral_movement_risks,
            'attack_surface': attack_surface,
            'behavioral_anomalies': behavioral_anomalies,
            'total_users_analyzed': len(self.analysis_results.get('users', [])),
            'policies_generated': len(self.generated_policies),
            'threat_score': self.threat_engine.get_threat_score()
        }
        
        return self.risk_metrics
    
    def export_results(self, output_file: str = None) -> str:
        """Export all results to JSON file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"zero_trust_analysis_{timestamp}.json"
        
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'analysis_summary': {
                'users_analyzed': len(self.analysis_results.get('users', [])),
                'policies_generated': len(self.generated_policies),
                'threats_detected': len(self.threat_engine.get_threats())
            },
            'trust_relationships': self.trust_relationships,
            'generated_policies': self.generated_policies,
            'risk_metrics': self.risk_metrics,
            'threat_intelligence': self.threat_engine.get_threats(),
            'network_topology': self.topology_mapper.get_topology()
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            print(f"[SUCCESS] Results exported to {output_file}")
            return output_file
        except Exception as e:
            print(f"[ERROR] Failed to export results: {str(e)}")
            return None
    
    def print_summary(self):
        """Print analysis summary to console"""
        print("\n" + "="*60)
        print("ZERO TRUST POLICY ANALYSIS SUMMARY")
        print("="*60)
        
        if self.risk_metrics:
            print(f"Users Analyzed: {self.risk_metrics.get('total_users_analyzed', 0)}")
            print(f"Policies Generated: {self.risk_metrics.get('policies_generated', 0)}")
            print(f"Over-privileged Users: {self.risk_metrics.get('over_privileged_users', 0)}")
            print(f"Behavioral Anomalies: {self.risk_metrics.get('behavioral_anomalies', 0)}")
            print(f"Lateral Movement Risks: {self.risk_metrics.get('lateral_movement_risks', 0)}")
            print(f"Attack Surface Size: {self.risk_metrics.get('attack_surface', 0)}")
            print(f"Threat Score: {self.risk_metrics.get('threat_score', 0)}")
        
        print("\nTop Risk Users:")
        high_risk_users = [
            rel for rel in self.trust_relationships 
            if rel.get('trust_level') == 'low'
        ][:5]
        
        for user in high_risk_users:
            print(f"  - {user.get('user', 'Unknown')}: Trust Score {user.get('trust_score', 0):.2f}")
        
        print("\nGenerated Policies:")
        for i, policy in enumerate(self.generated_policies[:3], 1):
            print(f"  {i}. {policy.get('title', 'Untitled Policy')} [{policy.get('risk_level', 'unknown')} risk]")
        
        if len(self.generated_policies) > 3:
            print(f"  ... and {len(self.generated_policies) - 3} more policies")
        
        print("="*60)

def main():
    """Main execution function"""
    if len(sys.argv) < 2:
        print("Usage: python ZeroTrustPolicyGenerator.py <network_log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    
    # Initialize the generator
    zt_generator = ZeroTrustPolicyGenerator()
    
    # Load and analyze logs
    if not zt_generator.load_network_logs(log_file):
        print("[ERROR] Failed to load network logs. Exiting.")
        sys.exit(1)
    
    # Perform analysis
    analysis_results = zt_generator.analyze_logs()
    
    # Generate policies
    policies = zt_generator.generate_policies()
    
    # Calculate risk metrics
    risk_metrics = zt_generator.calculate_risk_metrics()
    
    # Export results
    output_file = zt_generator.export_results()
    
    # Print summary
    zt_generator.print_summary()
    
    print(f"\n[SUCCESS] Analysis complete. Results saved to: {output_file}")

if __name__ == "__main__":
    main()
