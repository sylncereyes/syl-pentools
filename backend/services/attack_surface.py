"""Attack surface mapping and graph analysis"""
import asyncio
import json
import networkx as nx
from datetime import datetime, timezone
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict
import uuid

from core.celery_app import celery_app
from core.database import get_sync_db
from models.attack_surface import (
    AttackSurfaceNode, AttackSurfaceEdge, AttackSurfaceSnapshot,
    NodeType, EdgeType
)
from models.asset import Asset
from models.finding import Finding
from models.scan import Scan
from sqlalchemy.orm import Session


@dataclass
class GraphStats:
    """Graph statistics"""
    node_count: int
    edge_count: int
    asset_count: int
    vulnerability_count: int
    criticality_distribution: Dict[str, int]
    top_risk_nodes: List[Dict]
    disconnected_components: int


class AttackSurfaceMapper:
    """Build and analyze attack surface graph"""
    
    def __init__(self, workspace_id: str):
        self.workspace_id = workspace_id
        self.graph = nx.MultiDiGraph()
        self.nodes_map: Dict[str, AttackSurfaceNode] = {}
    
    def build_from_scans(self) -> nx.MultiDiGraph:
        """Build attack surface graph from scan data"""
        db: Session = next(get_sync_db())
        try:
            # Clear existing graph
            self.graph.clear()
            self.nodes_map.clear()
            
            # Get all assets
            assets = db.query(Asset).filter(
                Asset.workspace_id == self.workspace_id,
                Asset.deleted_at.is_(None)
            ).all()
            
            # Add asset nodes
            for asset in assets:
                self._add_asset_node(asset)
            
            # Get findings for vulnerabilities
            findings = db.query(Finding).filter(
                Finding.workspace_id == self.workspace_id
            ).all()
            
            # Add vulnerability nodes and edges
            for finding in findings:
                self._add_vulnerability_node(finding)
            
            # Get scans for network topology
            scans = db.query(Scan).filter(
                Scan.workspace_id == self.workspace_id
            ).all()
            
            # Add scan-derived edges
            for scan in scans:
                self._add_scan_edges(scan)
            
            # Add DNS relationships
            self._add_dns_edges()
            
            # Add technology edges
            self._add_technology_edges()
            
            # Add certificate edges
            self._add_certificate_edges()
            
            return self.graph
            
        finally:
            db.close()
    
    def _add_asset_node(self, asset: Asset):
        """Add asset as node"""
        node_id = f"asset_{asset.id}"
        
        node = AttackSurfaceNode(
            id=node_id,
            workspace_id=self.workspace_id,
            asset_id=asset.id,
            type=NodeType.ASSET,
            label=asset.target,
            value=asset.target,
            properties={
                'asset_type': asset.type.value if hasattr(asset.type, 'value') else asset.type,
                'risk_level': asset.risk_level.value if hasattr(asset.risk_level, 'value') else asset.risk_level,
                'risk_score': asset.risk_score,
                'total_scans': asset.total_scans,
                'vulnerabilities_count': asset.vulnerabilities_count,
                'critical_vulns': asset.critical_vulns,
                'high_vulns': asset.high_vulns,
                'medium_vulns': asset.medium_vulns,
                'low_vulns': asset.low_vulns,
                'open_ports_count': asset.open_ports_count,
            },
            risk_score=asset.risk_score / 100.0,
            criticality=self._calculate_criticality(asset),
            discovered_by='asset_management',
            discovered_at=asset.created_at,
            last_seen=asset.last_scanned_at or asset.updated_at,
            confidence=1.0,
        )
        
        self.graph.add_node(node_id, **{
            'type': NodeType.ASSET,
            'label': asset.target,
            'value': asset.target,
            'risk_score': asset.risk_score / 100.0,
            'criticality': self._calculate_criticality(asset),
            'data': node,
        })
        self.nodes_map[node_id] = node
    
    def _add_vulnerability_node(self, finding: Finding):
        """Add vulnerability as node and connect to asset"""
        vuln_id = f"vuln_{finding.id}"
        asset_id = f"asset_{finding.asset_id}"
        
        node = AttackSurfaceNode(
            id=vuln_id,
            workspace_id=self.workspace_id,
            asset_id=finding.asset_id,
            type=NodeType.VULNERABILITY,
            label=finding.title[:100],
            value=finding.id,
            properties={
                'severity': finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
                'status': finding.status.value if hasattr(finding.status, 'value') else finding.status,
                'cwe_id': finding.cwe_id,
                'cve_ids': finding.cve_ids,
                'cvss_score': finding.cvss_score,
                'source_scanner': finding.source_scanner,
                'source_rule_id': finding.source_rule_id,
            },
            risk_score=self._severity_to_score(finding.severity),
            criticality=self._severity_to_criticality(finding.severity),
            discovered_by=finding.source_scanner,
            discovered_at=finding.created_at,
            confidence=0.9,
        )
        
        self.graph.add_node(vuln_id, **{
            'type': NodeType.VULNERABILITY,
            'label': finding.title[:100],
            'value': finding.id,
            'risk_score': self._severity_to_score(finding.severity),
            'criticality': self._severity_to_criticality(finding.severity),
            'data': node,
        })
        self.nodes_map[vuln_id] = node
        
        # Connect asset -> vulnerability
        if asset_id in self.graph:
            edge = AttackSurfaceEdge(
                id=f"edge_{uuid.uuid4().hex[:12]}",
                workspace_id=self.workspace_id,
                source_id=asset_id,
                target_id=vuln_id,
                type=EdgeType.HAS_VULN,
                label='has vulnerability',
                properties={'finding_id': str(finding.id)},
                weight=1.0,
                discovered_by='finding_analysis',
                confidence=0.95,
            )
            self.graph.add_edge(asset_id, vuln_id, **{
                'type': EdgeType.HAS_VULN,
                'label': 'has vulnerability',
                'weight': 1.0,
                'data': edge,
            })
    
    def _add_scan_edges(self, scan: Scan):
        """Add edges from scan results"""
        # This would parse scan results for relationships
        # For now, add basic scan->target edge
        pass
    
    def _add_dns_edges(self):
        """Add DNS resolution edges"""
        # Find subdomain relationships
        asset_nodes = [n for n, d in self.graph.nodes(data=True) 
                      if d.get('type') == NodeType.ASSET]
        
        for asset_id in asset_nodes:
            asset_data = self.nodes_map.get(asset_id)
            if not asset_data:
                continue
            
            # Check if it's a subdomain
            value = asset_data.value
            parts = value.split('.')
            if len(parts) > 2:
                # Potential subdomain
                root_domain = '.'.join(parts[-2:])
                root_id = f"asset_{root_domain}"  # Would need to match
                
                if root_id in self.graph:
                    self.graph.add_edge(
                        root_id, asset_id,
                        type=EdgeType.DNS_POINTS,
                        label='dns points to',
                        weight=0.5,
                    )
    
    def _add_technology_edges(self):
        """Add technology stack edges"""
        # Connect assets that share technologies
        pass
    
    def _add_certificate_edges(self):
        """Add SSL certificate edges"""
        pass
    
    def _calculate_criticality(self, asset: Asset) -> str:
        """Calculate asset criticality"""
        if asset.critical_vulns > 0:
            return 'critical'
        elif asset.high_vulns > 0:
            return 'high'
        elif asset.medium_vulns > 0:
            return 'medium'
        elif asset.low_vulns > 0:
            return 'low'
        return 'info'
    
    def _severity_to_score(self, severity) -> float:
        """Convert severity to risk score"""
        sev_str = severity.value if hasattr(severity, 'value') else str(severity)
        scores = {'critical': 1.0, 'high': 0.8, 'medium': 0.5, 'low': 0.2, 'info': 0.1}
        return scores.get(sev_str.lower(), 0.1)
    
    def _severity_to_criticality(self, severity) -> str:
        """Convert severity to criticality"""
        sev_str = severity.value if hasattr(severity, 'value') else str(severity)
        return sev_str.lower()
    
    def save_to_db(self) -> AttackSurfaceSnapshot:
        """Save current graph as snapshot to database"""
        db: Session = next(get_sync_db())
        try:
            # Calculate stats
            stats = self.get_stats()
            
            # Serialize graph
            graph_data = nx.node_link_data(self.graph)
            
            snapshot = AttackSurfaceSnapshot(
                id=str(uuid.uuid4()),
                workspace_id=self.workspace_id,
                name=f"Attack Surface {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}",
                node_count=stats.node_count,
                edge_count=stats.edge_count,
                asset_count=stats.asset_count,
                vulnerability_count=stats.vulnerability_count,
                graph_data=graph_data,
            )
            
            db.add(snapshot)
            db.commit()
            db.refresh(snapshot)
            return snapshot
            
        finally:
            db.close()
    
    def get_stats(self) -> GraphStats:
        """Get graph statistics"""
        node_count = self.graph.number_of_nodes()
        edge_count = self.graph.number_of_edges()
        
        asset_count = sum(1 for n, d in self.graph.nodes(data=True) 
                         if d.get('type') == NodeType.ASSET)
        vuln_count = sum(1 for n, d in self.graph.nodes(data=True) 
                        if d.get('type') == NodeType.VULNERABILITY)
        
        # Criticality distribution
        crit_dist = defaultdict(int)
        for n, d in self.graph.nodes(data=True):
            crit = d.get('criticality', 'info')
            crit_dist[crit] += 1
        
        # Top risk nodes
        risk_nodes = []
        for n, d in self.graph.nodes(data=True):
            if d.get('type') == NodeType.VULNERABILITY:
                risk_nodes.append({
                    'id': n,
                    'label': d.get('label'),
                    'risk_score': d.get('risk_score', 0),
                    'criticality': d.get('criticality'),
                })
        
        risk_nodes.sort(key=lambda x: x['risk_score'], reverse=True)
        
        # Connected components
        undirected = self.graph.to_undirected()
        components = nx.number_connected_components(undirected)
        
        return GraphStats(
            node_count=node_count,
            edge_count=edge_count,
            asset_count=asset_count,
            vulnerability_count=vuln_count,
            criticality_distribution=dict(crit_dist),
            top_risk_nodes=risk_nodes[:10],
            disconnected_components=components,
        )
    
    def find_attack_paths(self, target_asset_id: str, max_depth: int = 5) -> List[List[str]]:
        """Find attack paths to a target asset"""
        target_node = f"asset_{target_asset_id}"
        
        if target_node not in self.graph:
            return []
        
        # Find all paths from entry points (internet-facing assets)
        entry_points = [
            n for n, d in self.graph.nodes(data=True)
            if d.get('type') == NodeType.ASSET and 
            d.get('data', {}).properties.get('is_internet_facing', False)
        ]
        
        paths = []
        for entry in entry_points:
            try:
                for path in nx.all_simple_paths(
                    self.graph, entry, target_node, cutoff=max_depth
                ):
                    paths.append(path)
            except nx.NetworkXNoPath:
                continue
        
        return paths[:100]  # Limit results
    
    def get_high_risk_assets(self, limit: int = 10) -> List[Dict]:
        """Get highest risk assets"""
        assets = []
        for n, d in self.graph.nodes(data=True):
            if d.get('type') == NodeType.ASSET:
                # Calculate risk based on vulnerabilities
                vuln_edges = list(self.graph.out_edges(n, data=True))
                vuln_count = len([e for e in vuln_edges if e[2].get('type') == EdgeType.HAS_VULN])
                
                critical_vulns = sum(1 for _, _, data in vuln_edges 
                                   if data.get('data', {}).properties.get('severity') == 'critical')
                high_vulns = sum(1 for _, _, data in vuln_edges 
                               if data.get('data', {}).properties.get('severity') == 'high')
                
                assets.append({
                    'id': n,
                    'label': d.get('label'),
                    'value': d.get('value'),
                    'vulnerability_count': vuln_count,
                    'critical_vulns': critical_vulns,
                    'high_vulns': high_vulns,
                    'risk_score': d.get('risk_score', 0),
                    'criticality': d.get('criticality'),
                })
        
        assets.sort(key=lambda x: (x['critical_vulns'], x['high_vulns'], x['risk_score']), reverse=True)
        return assets[:limit]


# Celery task for building attack surface
@celery_app.task
def build_attack_surface_task(workspace_id: str):
    """Build attack surface graph for workspace"""
    mapper = AttackSurfaceMapper(workspace_id)
    mapper.build_from_scans()
    snapshot = mapper.save_to_db()
    return {'status': 'completed', 'snapshot_id': str(snapshot.id)}


@celery_app.task
def find_attack_paths_task(workspace_id: str, target_asset_id: str):
    """Find attack paths to target asset"""
    mapper = AttackSurfaceMapper(workspace_id)
    mapper.build_from_scans()
    paths = mapper.find_attack_paths(target_asset_id)
    return {'paths': paths}


def get_attack_surface_stats(workspace_id: str) -> GraphStats:
    """Get attack surface statistics"""
    mapper = AttackSurfaceMapper(workspace_id)
    mapper.build_from_scans()
    return mapper.get_stats()


def get_high_risk_assets(workspace_id: str, limit: int = 10) -> List[Dict]:
    """Get high risk assets"""
    mapper = AttackSurfaceMapper(workspace_id)
    mapper.build_from_scans()
    return mapper.get_high_risk_assets(limit)