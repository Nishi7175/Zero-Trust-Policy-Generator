#!/usr/bin/env python3
"""
NetworkTopologyMapper.py - Network Topology Analysis Module
Maps network topology and identifies lateral movement risks
"""

from typing import Dict, List, Set, Tuple
from collections import defaultdict
import json

class NetworkTopologyMapper:
    """Maps and analyzes network topology for security risks"""
    
    def __init__(self):
        self.topology = {
            'nodes': [],
            'edges': [],
            'criticality': {},
            'segments': {}
        }
        self.risk_paths = []
        self.isolation_candidates = []
        
    def map_topology(self, analysis_data: Dict) -> Dict:
        """Map network topology from analysis data"""
        parsed_logs = analysis_data.get('parsed_logs', [])
        
        print(f"[INFO] Mapping network topology from {len(parsed_logs)} log entries...")
        
        # Initialize topology structures
        nodes = set()
        edges = []
        criticality_scores = {}
        connection_matrix = defaultdict(set)
        
        # Process each log entry to build network map
        for log_entry in parsed_logs:
            source_ip = log_entry.get('ip', '')
            resource = log_entry.get('resource', '')
            user = log_entry.get('user', '').replace('user:', '')
            sensitivity = log_entry.get('sensitivity', 'low')
            protocol = log_entry.get('protocol', 'unknown')
            port = log_entry.get('port', 'unknown')
            
            if not source_ip or not resource:
                continue
            
            # Add nodes
            source_node = f"{source_ip}"
            target_node = f"{resource}"
            
            nodes.add(source_node)
            nodes.add(target_node)
            
            # Create edge with metadata
            edge = {
                'source': source_node,
                'target': target_node,
                'user': user,
                'protocol': protocol,
                'port': port,
                'weight': self._calculate_edge_weight(sensitivity, log_entry),
                'encrypted': log_entry.get('encryption', '') != '',
                'timestamp': log_entry.get('timestamp', ''),
                'sensitivity': sensitivity
            }
            edges.append(edge)
            
            # Track connections for analysis
            connection_matrix[source_node].add(target_node)
            connection_matrix[target_node].add(source_node)
            
            # Calculate criticality scores
            criticality_scores[target_node] = max(
                criticality_scores.get(target_node, 0.0),
                self._calculate_criticality_score(sensitivity, log_entry)
            )
            
            # Set minimum criticality for source nodes
            if source_node not in criticality_scores:
                criticality_scores[source_node] = 0.2
        
        # Store topology
        self.topology = {
            'nodes': list(nodes),
            'edges': edges,
            'criticality': criticality_scores,
            'connection_matrix': {k: list(v) for k, v in connection_matrix.items()},
            'segments': self._identify_network_segments(nodes, connection_matrix)
        }
        
        # Analyze topology for risks
        self.risk_paths = self._calculate_risk_paths()
        self.isolation_candidates = self._identify_isolation_candidates()
        
        print(f"[INFO] Mapped topology: {len(nodes)} nodes, {len(edges)} edges")
        print(f"[INFO] Identified {len(self.risk_paths)} risk paths")
        print(f"[INFO] Found {len(self.isolation_candidates)} isolation candidates")
        
        return self.get_topology()
    
    def _calculate_edge_weight(self, sensitivity: str, log_entry: Dict) -> float:
        """Calculate edge weight based on sensitivity and other factors"""
        base_weight = {
            'critical': 3.0,
            'high': 2.0,
            'medium': 1.5,
            'low': 1.0,
            'public': 0.5
        }.get(sensitivity, 1.0)
        
        # Increase weight for risky activities
        if log_entry.get('privilege_escalation') == 'detected':
            base_weight += 1.0
        
        if log_entry.get('lateral_movement') == 'attempt':
            base_weight += 1.5
        
        if log_entry.get('success') == 'false':
            base_weight += 0.5  # Failed attempts indicate probing
        
        return base_weight
    
    def _calculate_criticality_score(self, sensitivity: str, log_entry: Dict) -> float:
        """Calculate node criticality score"""
        base_score = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.6,
            'low': 0.4,
            'public': 0.2
        }.get(sensitivity, 0.4)
        
        # Adjust based on resource type
        resource = log_entry.get('resource', '').lower()
        
        if any(keyword in resource for keyword in ['database', 'db', 'sql']):
            base_score += 0.2
        
        if any(keyword in resource for keyword in ['admin', 'root', 'config']):
            base_score += 0.3
        
        if any(keyword in resource for keyword in ['finance', 'payroll', 'hr']):
            base_score += 0.2
        
        if any(keyword in resource for keyword in ['backup', 'archive']):
            base_score += 0.1
        
        return min(1.0, base_score)
    
    def _identify_network_segments(self, nodes: Set[str], 
                                 connection_matrix: Dict[str, Set[str]]) -> Dict:
        """Identify logical network segments"""
        segments = {}
        
        # Simple segmentation based on IP ranges
        ip_segments = defaultdict(list)
        
        for node in nodes:
            if self._is_ip_address(node):
                # Extract network segment (first 3 octets for IPv4)
                ip_parts = node.split('.')
                if len(ip_parts) >= 3:
                    segment_key = '.'.join(ip_parts[:3]) + '.0/24'
                    ip_segments[segment_key].append(node)
            else:
                # Resource-based segmentation
                if 'database' in node.lower():
                    segment_key = 'database_tier'
                elif 'web' in node.lower() or 'http' in node.lower():
                    segment_key = 'web_tier'
                elif 'file' in node.lower():
                    segment_key = 'file_services'
                else:
                    segment_key = 'application_tier'
                
                if segment_key not in ip_segments:
                    ip_segments[segment_key] = []
                ip_segments[segment_key].append(node)
        
        # Calculate segment risk scores
        for segment, segment_nodes in ip_segments.items():
            segment_criticality = sum(
                self.topology['criticality'].get(node, 0.0) 
                for node in segment_nodes
            ) / len(segment_nodes) if segment_nodes else 0.0
            
            segments[segment] = {
                'nodes': segment_nodes,
                'node_count': len(segment_nodes),
                'criticality': round(segment_criticality, 2),
                'isolation_recommended': segment_criticality > 0.7
            }
        
        return segments
    
    def _is_ip_address(self, address: str) -> bool:
        """Check if string is an IP address"""
        try:
            parts = address.split('.')
            return (len(parts) == 4 and 
                   all(0 <= int(part) <= 255 for part in parts))
        except (ValueError, AttributeError):
            return False
    
    def _calculate_risk_paths(self) -> List[Dict]:
        """Calculate potential lateral movement risk paths"""
        risk_paths = []
        
        # Find high-risk connections
        for edge in self.topology['edges']:
            source = edge['source']
            target = edge['target']
            weight = edge['weight']
            
            source_criticality = self.topology['criticality'].get(source, 0.0)
            target_criticality = self.topology['criticality'].get(target, 0.0)
            
            # Calculate risk score for this path
            risk_score = (
                weight * 0.4 +
                target_criticality * 0.4 +
                source_criticality * 0.2
            )
            
            # Only include paths above threshold
            if risk_score >= 1.5:
                risk_path = {
                    'source': source,
                    'target': target,
                    'risk_score': round(risk_score, 2),
                    'path': f"{source} -> {target}",
                    'encrypted': edge['encrypted'],
                    'protocol': edge['protocol'],
                    'port': edge['port'],
                    'user': edge['user'],
                    'criticality_source': round(source_criticality, 2),
                    'criticality_target': round(target_criticality, 2),
                    'mitigation_priority': self._get_mitigation_priority(risk_score)
                }
                risk_paths.append(risk_path)
        
        # Sort by risk score (highest first)
        risk_paths.sort(key=lambda x: x['risk_score'], reverse=True)
        
        return risk_paths[:20]  # Limit to top 20 risk paths
    
    def _get_mitigation_priority(self, risk_score: float) -> str:
        """Determine mitigation priority based on risk score"""
        if risk_score >= 2.5:
            return 'immediate'
        elif risk_score >= 2.0:
            return 'high'
        elif risk_score >= 1.7:
            return 'medium'
        else:
            return 'low'
    
    def _identify_isolation_candidates(self) -> List[Dict]:
        """Identify nodes that should be isolated"""
        candidates = []
        
        for node, criticality in self.topology['criticality'].items():
            if criticality >= 0.7:  # High criticality threshold
                # Count connections
                connections = len(self.topology['connection_matrix'].get(node, []))
                
                # Calculate isolation priority
                isolation_score = criticality + (connections * 0.1)
                
                candidate = {
                    'node': node,
                    'criticality': round(criticality, 2),
                    'connections': connections,
                    'isolation_score': round(isolation_score, 2),
                    'isolation_priority': self._get_isolation_priority(isolation_score),
                    'recommended_controls': self._get_isolation_controls(criticality, connections)
                }
                candidates.append(candidate)
        
        # Sort by isolation score (highest first)
        candidates.sort(key=lambda x: x['isolation_score'], reverse=True)
        
        return candidates
    
    def _get_isolation_priority(self, isolation_score: float) -> str:
        """Determine isolation priority"""
        if isolation_score >= 1.5:
            return 'critical'
        elif isolation_score >= 1.2:
            return 'high'
        elif isolation_score >= 0.9:
            return 'medium'
        else:
            return 'low'
    
    def _get_isolation_controls(self, criticality: float, connections: int) -> List[str]:
        """Get recommended isolation controls"""
        controls = []
        
        if criticality >= 0.9:
            controls.extend([
                'Deploy dedicated network segment (VLAN)',
                'Implement default-deny firewall rules',
                'Enable network access control (NAC)',
                'Require encrypted communications (IPSec/TLS)'
            ])
        elif criticality >= 0.7:
            controls.extend([
                'Create isolated network zone',
                'Implement restrictive firewall rules',
                'Enable network monitoring and logging'
            ])
        
        if connections > 10:
            controls.append('Review and reduce unnecessary network connections')
        
        if connections > 20:
            controls.append('Implement connection rate limiting')
        
        return controls
    
    def get_topology(self) -> Dict:
        """Get complete topology data"""
        return {
            'nodes': self.topology['nodes'],
            'edges': self.topology['edges'],
            'criticality': self.topology['criticality'],
            'segments': self.topology['segments'],
            'risk_paths': self.risk_paths,
            'isolation_candidates': self.isolation_candidates,
            'statistics': self._get_topology_statistics()
        }
    
    def get_risk_paths(self) -> List[Dict]:
        """Get identified risk paths"""
        return self.risk_paths
    
    def get_isolation_candidates(self) -> List[Dict]:
        """Get isolation candidates"""
        return self.isolation_candidates
    
    def _get_topology_statistics(self) -> Dict:
        """Calculate topology statistics"""
        total_nodes = len(self.topology['nodes'])
        total_edges = len(self.topology['edges'])
        
        # Count nodes by criticality
        critical_nodes = sum(1 for c in self.topology['criticality'].values() if c >= 0.8)
        high_criticality_nodes = sum(1 for c in self.topology['criticality'].values() if 0.6 <= c < 0.8)
        
        # Calculate average criticality
        avg_criticality = (
            sum(self.topology['criticality'].values()) / total_nodes
            if total_nodes > 0 else 0.0
        )
        
        # Count encrypted connections
        encrypted_edges = sum(1 for edge in self.topology['edges'] if edge['encrypted'])
        encryption_ratio = encrypted_edges / total_edges if total_edges > 0 else 0.0
        
        return {
            'total_nodes': total_nodes,
            'total_edges': total_edges,
            'critical_nodes': critical_nodes,
            'high_criticality_nodes': high_criticality_nodes,
            'average_criticality': round(avg_criticality, 2),
            'risk_paths_identified': len(self.risk_paths),
            'isolation_candidates': len(self.isolation_candidates),
            'network_segments': len(self.topology['segments']),
            'encryption_ratio': round(encryption_ratio, 2),
            'total_protocols': len(set(edge['protocol'] for edge in self.topology['edges']))
        }
    
    def get_node_details(self, node: str) -> Dict:
        """Get detailed information about a specific node"""
        if node not in self.topology['nodes']:
            return None
        
        # Find all edges connected to this node
        incoming_edges = [e for e in self.topology['edges'] if e['target'] == node]
        outgoing_edges = [e for e in self.topology['edges'] if e['source'] == node]
        
        # Get connections
        connections = self.topology['connection_matrix'].get(node, [])
        
        # Find network segment
        node_segment = None
        for segment_name, segment_data in self.topology['segments'].items():
            if node in segment_data['nodes']:
                node_segment = segment_name
                break
        
        return {
            'node': node,
            'criticality': self.topology['criticality'].get(node, 0.0),
            'total_connections': len(connections),
            'incoming_connections': len(incoming_edges),
            'outgoing_connections': len(outgoing_edges),
            'connected_nodes': connections,
            'network_segment': node_segment,
            'protocols_used': list(set(
                e['protocol'] for e in incoming_edges + outgoing_edges
            )),
            'encryption_usage': {
                'encrypted_connections': len([
                    e for e in incoming_edges + outgoing_edges if e['encrypted']
                ]),
                'total_connections': len(incoming_edges + outgoing_edges)
            },
            'risk_involvement': len([
                rp for rp in self.risk_paths 
                if rp['source'] == node or rp['target'] == node
            ])
        }
    
    def export_topology(self, filename: str = None, format_type: str = 'json') -> str:
        """Export topology data to file"""
        from datetime import datetime
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_topology_{timestamp}.{format_type}"
        
        export_data = {
            'generation_timestamp': datetime.now().isoformat(),
            'topology': self.get_topology()
        }
        
        try:
            if format_type.lower() == 'json':
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
            else:
                # Could add other formats like GraphML, DOT, etc.
                print(f"[WARNING] Format {format_type} not supported, using JSON")
                filename = filename.replace(f'.{format_type}', '.json')
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
            
            print(f"[SUCCESS] Network topology exported to {filename}")
            return filename
            
        except Exception as e:
            print(f"[ERROR] Failed to export topology: {str(e)}")
            return None
    
    def generate_topology_report(self) -> str:
        """Generate human-readable topology analysis report"""
        stats = self._get_topology_statistics()
        
        report = []
        report.append("=" * 60)
        report.append("NETWORK TOPOLOGY ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("")
        
        report.append("TOPOLOGY OVERVIEW:")
        report.append(f"  Total Network Nodes: {stats['total_nodes']}")
        report.append(f"  Total Connections: {stats['total_edges']}")
        report.append(f"  Network Segments: {stats['network_segments']}")
        report.append(f"  Protocols Identified: {stats['total_protocols']}")
        report.append(f"  Encryption Ratio: {stats['encryption_ratio']:.1%}")
        report.append("")
        
        report.append("CRITICALITY ANALYSIS:")
        report.append(f"  Critical Assets (≥0.8): {stats['critical_nodes']}")
        report.append(f"  High-Value Assets (0.6-0.8): {stats['high_criticality_nodes']}")
        report.append(f"  Average Asset Criticality: {stats['average_criticality']:.2f}")
        report.append("")
        
        report.append("RISK ASSESSMENT:")
        report.append(f"  High-Risk Paths: {len(self.risk_paths)}")
        report.append(f"  Isolation Candidates: {len(self.isolation_candidates)}")
        report.append("")
        
        if self.risk_paths:
            report.append("TOP RISK PATHS:")
            for i, path in enumerate(self.risk_paths[:5], 1):
                report.append(f"  {i}. {path['path']} (Risk: {path['risk_score']:.1f})")
                report.append(f"     Priority: {path['mitigation_priority'].upper()}")
            report.append("")
        
        if self.isolation_candidates:
            report.append("ISOLATION RECOMMENDATIONS:")
            for i, candidate in enumerate(self.isolation_candidates[:5], 1):
                report.append(f"  {i}. {candidate['node']} (Priority: {candidate['isolation_priority'].upper()})")
                report.append(f"     Criticality: {candidate['criticality']:.2f}, Connections: {candidate['connections']}")
            report.append("")
        
        report.append("NETWORK SEGMENTS:")
        for segment, data in self.topology['segments'].items():
            report.append(f"  {segment}: {data['node_count']} nodes, Criticality: {data['criticality']:.2f}")
        
        return "\n".join(report)
