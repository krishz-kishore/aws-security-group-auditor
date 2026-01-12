"""
AWS Security Group Report Generator
Analyzes collected AWS security group data and generates professional PDF report
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
import pandas as pd
from jinja2 import Environment, FileSystemLoader
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError) as e:
    WEASYPRINT_AVAILABLE = False
    print(f"Warning: WeasyPrint not available: {e}")
    print("PDF generation will be skipped. HTML report will still be generated.")
import plotly.graph_objects as go
import plotly.express as px


class SecurityGroupAnalyzer:
    """Analyzes security group data for security risks"""
    
    # Industry-standard risky ports
    RISKY_PORTS = {
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        135: "MS RPC",
        137: "NetBIOS",
        138: "NetBIOS",
        139: "NetBIOS",
        443: "HTTPS",
        445: "SMB",
        1433: "SQL Server",
        1434: "SQL Server",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP Alt",
        8443: "HTTPS Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }
    
    # Critical ports that should NEVER be open to 0.0.0.0/0
    CRITICAL_PORTS = {22, 23, 3389, 1433, 3306, 5432, 6379, 27017, 9200}
    
    # Management/admin ports
    MANAGEMENT_PORTS = {22, 3389, 5900, 5985, 5986}
    
    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.findings = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        self.stats = {
            'total_sgs': 0,
            'unused_sgs': 0,
            'risky_rules': 0,
            'overlapping_rules': 0
        }
        self.all_security_groups = []  # Comprehensive list of all SGs with details
        
    def analyze(self) -> Dict[str, Any]:
        """Perform comprehensive security analysis"""
        print("Starting security analysis...")
        
        for region_data in self.data['regions']:
            region = region_data['region_name']
            print(f"  Analyzing region: {region}")
            
            security_groups = region_data.get('security_groups', [])
            network_interfaces = region_data.get('network_interfaces', [])
            
            self.stats['total_sgs'] += len(security_groups)
            
            # Build attachment mapping
            sg_attachments = self._build_attachment_map(network_interfaces)
            
            for sg in security_groups:
                self._analyze_security_group(sg, region, sg_attachments)
                # Collect comprehensive SG data for table
                self._collect_sg_summary(sg, region, sg_attachments)
        
        print("  Analysis complete!")
        return {
            'findings': self.findings,
            'stats': self.stats,
            'all_security_groups': self.all_security_groups
        }
    
    def _build_attachment_map(self, network_interfaces: List[Dict]) -> Dict[str, List[str]]:
        """Build map of security group ID to attached resources"""
        attachments = {}
        
        for eni in network_interfaces:
            eni_id = eni.get('NetworkInterfaceId', 'unknown')
            description = eni.get('Description', '')
            
            for group in eni.get('Groups', []):
                sg_id = group['GroupId']
                if sg_id not in attachments:
                    attachments[sg_id] = []
                attachments[sg_id].append({
                    'eni_id': eni_id,
                    'description': description,
                    'private_ip': eni.get('PrivateIpAddress', 'N/A')
                })
        
        return attachments
    
    def _analyze_security_group(self, sg: Dict, region: str, attachments: Dict):
        """Analyze individual security group for risks"""
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']
        vpc_id = sg.get('VpcId', 'EC2-Classic')
        
        # Check if unused
        attached_resources = attachments.get(sg_id, [])
        if not attached_resources and sg_name != 'default':
            self.stats['unused_sgs'] += 1
            self.findings['info'].append({
                'type': 'Unused Security Group',
                'severity': 'INFO',
                'region': region,
                'sg_id': sg_id,
                'sg_name': sg_name,
                'vpc_id': vpc_id,
                'description': f"Security group '{sg_name}' has no attached resources",
                'recommendation': 'Consider removing unused security groups to reduce complexity'
            })
        
        # Analyze ingress rules
        for rule in sg.get('IpPermissions', []):
            self._analyze_rule(rule, sg, region, 'ingress', attached_resources)
        
        # Analyze egress rules (less critical but still important)
        for rule in sg.get('IpPermissionsEgress', []):
            self._analyze_rule(rule, sg, region, 'egress', attached_resources)
    
    def _analyze_rule(self, rule: Dict, sg: Dict, region: str, direction: str, attachments: List):
        """Analyze individual security group rule"""
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']
        vpc_id = sg.get('VpcId', 'EC2-Classic')
        
        from_port = rule.get('FromPort', 'All')
        to_port = rule.get('ToPort', 'All')
        ip_protocol = rule.get('IpProtocol', 'All')
        
        if ip_protocol == '-1':
            ip_protocol = 'All'
            port_display = 'All Ports'
        elif from_port == to_port:
            port_display = f"Port {from_port}"
        else:
            port_display = f"Ports {from_port}-{to_port}"
        
        # Check IPv4 ranges
        for ip_range in rule.get('IpRanges', []):
            cidr = ip_range.get('CidrIp', '')
            self._check_risky_cidr(
                cidr, from_port, to_port, ip_protocol, port_display,
                sg_id, sg_name, vpc_id, region, direction, attachments, ip_range
            )
        
        # Check IPv6 ranges
        for ip_range in rule.get('Ipv6Ranges', []):
            cidr = ip_range.get('CidrIpv6', '')
            self._check_risky_cidr(
                cidr, from_port, to_port, ip_protocol, port_display,
                sg_id, sg_name, vpc_id, region, direction, attachments, ip_range
            )
    
    def _check_risky_cidr(self, cidr: str, from_port: Any, to_port: Any, 
                          ip_protocol: str, port_display: str, sg_id: str, 
                          sg_name: str, vpc_id: str, region: str, direction: str,
                          attachments: List, ip_range: Dict):
        """Check if CIDR range poses security risk"""
        
        is_public = cidr in ['0.0.0.0/0', '::/0']
        
        if not is_public:
            return  # Not exposed to internet
        
        if direction == 'egress':
            # Egress to internet is common, only flag if all protocols
            if ip_protocol == 'All':
                self.findings['low'].append({
                    'type': 'Permissive Egress Rule',
                    'severity': 'LOW',
                    'region': region,
                    'sg_id': sg_id,
                    'sg_name': sg_name,
                    'vpc_id': vpc_id,
                    'rule': f"{direction.upper()}: {port_display} ({ip_protocol})  {cidr}",
                    'description': f"All outbound traffic allowed to internet",
                    'attached_resources': len(attachments),
                    'recommendation': 'Consider restricting egress to specific ports/protocols'
                })
            return
        
        # Ingress rules from internet
        self.stats['risky_rules'] += 1
        
        # Determine severity
        severity = 'MEDIUM'
        risk_type = 'Internet-Exposed Port'
        
        # Check for critical ports
        if isinstance(from_port, int):
            if from_port in self.CRITICAL_PORTS or to_port in self.CRITICAL_PORTS:
                severity = 'CRITICAL'
                risk_type = 'Critical Port Exposed to Internet'
            elif from_port in self.MANAGEMENT_PORTS or to_port in self.MANAGEMENT_PORTS:
                severity = 'HIGH'
                risk_type = 'Management Port Exposed to Internet'
            elif from_port in self.RISKY_PORTS or to_port in self.RISKY_PORTS:
                severity = 'HIGH'
                risk_type = 'Risky Port Exposed to Internet'
        
        # All protocols/ports open is critical
        if ip_protocol == 'All':
            severity = 'CRITICAL'
            risk_type = 'All Protocols/Ports Open to Internet'
        
        port_name = ''
        if isinstance(from_port, int) and from_port in self.RISKY_PORTS:
            port_name = f" ({self.RISKY_PORTS[from_port]})"
        
        finding = {
            'type': risk_type,
            'severity': severity,
            'region': region,
            'sg_id': sg_id,
            'sg_name': sg_name,
            'vpc_id': vpc_id,
            'rule': f"INGRESS: {port_display}{port_name} ({ip_protocol})  {cidr}",
            'description': ip_range.get('Description', 'No description provided'),
            'attached_resources': len(attachments),
            'attachments': attachments[:5],  # Limit to first 5 for display
            'recommendation': self._get_recommendation(from_port, ip_protocol)
        }
        
        self.findings[severity.lower()].append(finding)
    
    def _get_recommendation(self, port: Any, protocol: str) -> str:
        """Get security recommendation based on finding"""
        if protocol == 'All':
            return 'URGENT: Restrict to specific protocols and ports. Use VPN or bastion host for management access.'
        
        if isinstance(port, int):
            if port in {22, 3389}:
                return 'Use AWS Systems Manager Session Manager or VPN instead of direct internet access'
            elif port in {1433, 3306, 5432, 27017, 6379, 9200}:
                return 'Database should NEVER be exposed to internet. Use VPN, VPC peering, or PrivateLink'
            elif port == 23:
                return 'Telnet is insecure and deprecated. Use SSH instead and restrict access'
        
        return 'Restrict source to specific IP addresses or use AWS security services (CloudFront, ALB, etc.)'
    
    def _collect_sg_summary(self, sg: Dict, region: str, attachments: Dict):
        """Collect comprehensive security group data for summary table"""
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']
        vpc_id = sg.get('VpcId', 'EC2-Classic')
        attached_resources = attachments.get(sg_id, [])
        
        # Collect all ingress rules
        ingress_rules = []
        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', 'All')
            to_port = rule.get('ToPort', 'All')
            ip_protocol = rule.get('IpProtocol', 'All')
            
            if ip_protocol == '-1':
                port_display = 'All Ports'
            elif from_port == to_port:
                port_display = str(from_port)
            else:
                port_display = f"{from_port}-{to_port}"
            
            # Get all CIDR ranges
            cidrs = []
            for ip_range in rule.get('IpRanges', []):
                cidrs.append(ip_range.get('CidrIp', ''))
            for ip_range in rule.get('Ipv6Ranges', []):
                cidrs.append(ip_range.get('CidrIpv6', ''))
            
            if cidrs:
                ingress_rules.append({
                    'port': port_display,
                    'protocol': ip_protocol if ip_protocol != '-1' else 'All',
                    'source': ', '.join(cidrs)
                })
        
        self.all_security_groups.append({
            'sg_id': sg_id,
            'sg_name': sg_name,
            'region': region,
            'vpc_id': vpc_id,
            'attached_resources_count': len(attached_resources),
            'ingress_rules': ingress_rules,
            'is_used': len(attached_resources) > 0
        })


def generate_charts(analysis: Dict, output_dir: Path) -> Dict[str, str]:
    """Generate charts for the report"""
    charts = {}
    findings = analysis['findings']
    stats = analysis['stats']
    
    # Severity distribution pie chart
    severity_counts = {
        'Critical': len(findings['critical']),
        'High': len(findings['high']),
        'Medium': len(findings['medium']),
        'Low': len(findings['low']),
        'Info': len(findings['info'])
    }
    
    colors = ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d']
    
    fig = go.Figure(data=[go.Pie(
        labels=list(severity_counts.keys()),
        values=list(severity_counts.values()),
        hole=.3,
        marker=dict(colors=colors)
    )])
    fig.update_layout(
        title="Findings by Severity",
        showlegend=True,
        height=300,
        margin=dict(l=20, r=20, t=40, b=20)
    )
    chart_path = output_dir / 'severity_chart.png'
    fig.write_image(str(chart_path), width=600, height=300)
    charts['severity'] = str(chart_path)
    
    # Stats bar chart
    fig = go.Figure(data=[go.Bar(
        x=['Total Security Groups', 'Unused Groups', 'Risky Rules'],
        y=[stats['total_sgs'], stats['unused_sgs'], stats['risky_rules']],
        marker_color=['#007bff', '#6c757d', '#dc3545']
    )])
    fig.update_layout(
        title="Security Group Statistics",
        yaxis_title="Count",
        showlegend=False,
        height=300,
        margin=dict(l=20, r=20, t=40, b=20)
    )
    chart_path = output_dir / 'stats_chart.png'
    fig.write_image(str(chart_path), width=600, height=300)
    charts['stats'] = str(chart_path)
    
    return charts


def generate_report(json_file: str, output_dir: str = 'output'):
    """Generate comprehensive security report from JSON data"""
    
    print("AWS Security Group Audit Report Generator")
    print("=" * 50)
    print()
    
    # Load data
    print(f"Loading data from: {json_file}")
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    # Analyze
    analyzer = SecurityGroupAnalyzer(data)
    analysis = analyzer.analyze()
    
    # Setup output directory
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)
    
    # Generate charts
    print("Generating visualizations...")
    charts = generate_charts(analysis, output_path)
    
    # Prepare template data
    print("Preparing report data...")
    
    # Separate used and unused security groups for the table
    used_sgs = [sg for sg in analysis['all_security_groups'] if sg['is_used']]
    unused_sgs = [sg for sg in analysis['all_security_groups'] if not sg['is_used']]
    
    report_data = {
        'scan_date': datetime.fromisoformat(data['scan_timestamp'].replace('Z', '+00:00')).strftime('%B %d, %Y %H:%M UTC'),
        'generated_date': datetime.now().strftime('%B %d, %Y %H:%M'),
        'account_id': data['account_id'],
        'account_alias': data['account_alias'],
        'total_regions': len(data['regions']),
        'stats': analysis['stats'],
        'findings': analysis['findings'],
        'charts': charts,
        'severity_counts': {
            'critical': len(analysis['findings']['critical']),
            'high': len(analysis['findings']['high']),
            'medium': len(analysis['findings']['medium']),
            'low': len(analysis['findings']['low']),
            'info': len(analysis['findings']['info'])
        },
        'used_security_groups': used_sgs,
        'unused_security_groups': unused_sgs
    }
    
    # Generate HTML
    print("Generating HTML report...")
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report_template.html')
    html_content = template.render(**report_data)
    
    html_file = output_path / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"  ✓ HTML report: {html_file}")
    
    # Generate PDF (if WeasyPrint is available)
    if WEASYPRINT_AVAILABLE:
        try:
            print("Converting to PDF...")
            pdf_file = html_file.with_suffix('.pdf')
            HTML(string=html_content, base_url=str(output_path)).write_pdf(pdf_file)
            print(f"  ✓ PDF report: {pdf_file}")
        except Exception as e:
            print(f"  ⚠ PDF generation failed: {e}")
            print(f"  ℹ You can open the HTML file in a browser and use 'Print to PDF'")
    else:
        print("  ℹ PDF generation skipped (WeasyPrint not available)")
        print(f"  ℹ Open {html_file.name} in browser and use 'Print to PDF'")
    
    print()
    print("=" * 50)
    print("Report generation complete!")
    print(f"  - Critical findings: {report_data['severity_counts']['critical']}")
    print(f"  - High findings: {report_data['severity_counts']['high']}")
    print(f"  - Medium findings: {report_data['severity_counts']['medium']}")
    print(f"  - Total security groups: {analysis['stats']['total_sgs']}")
    print(f"  - Unused security groups: {analysis['stats']['unused_sgs']}")
    print("=" * 50)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python report_generator.py <json_file>")
        print("Example: python report_generator.py sg_audit_data_20260112_143022.json")
        sys.exit(1)
    
    json_file = sys.argv[1]
    
    if not os.path.exists(json_file):
        print(f"Error: File not found: {json_file}")
        sys.exit(1)
    
    generate_report(json_file)
