"""Report generation service - PDF, DOCX, HTML, CSV, JSON"""
import os
import json
import csv
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass
import uuid

from docx import Document
from docx.shared import Inches, Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn

from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Image, ListFlowable, ListItem
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY

from jinja2 import Environment, FileSystemLoader, BaseLoader
from core.database import get_sync_db
from models.report import Report, ReportTemplate, ReportFormat, ReportStatus
from models.finding import Finding, FindingSeverity, FindingStatus
from models.scan import Scan
from models.asset import Asset
from sqlalchemy.orm import Session


@dataclass
class ReportData:
    """Data structure for report generation"""
    title: str
    description: str
    workspace_name: str
    generated_at: datetime
    generated_by: str
    scans: List[Dict]
    findings: List[Dict]
    assets: List[Dict]
    stats: Dict[str, int]
    compliance_frameworks: List[str]
    compliance_mapping: Dict[str, Any]
    branding: Dict[str, Any]


class ReportGenerator:
    """Main report generator class"""
    
    def __init__(self, templates_dir: str = "/app/templates", reports_dir: str = "/app/reports"):
        self.templates_dir = Path(templates_dir)
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Jinja2 environment for HTML templates
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir / "html")),
            autoescape=True,
        )
    
    def generate(self, report: Report, db: Session) -> str:
        """Generate report in specified format"""
        # Update status
        report.status = ReportStatus.GENERATING
        db.commit()
        
        try:
            # Collect data
            data = self._collect_report_data(report, db)
            
            # Generate based on format
            if report.format == ReportFormat.PDF:
                file_path = self._generate_pdf(data, report)
            elif report.format == ReportFormat.DOCX:
                file_path = self._generate_docx(data, report)
            elif report.format == ReportFormat.HTML:
                file_path = self._generate_html(data, report)
            elif report.format == ReportFormat.CSV:
                file_path = self._generate_csv(data, report)
            elif report.format == ReportFormat.JSON:
                file_path = self._generate_json(data, report)
            else:
                raise ValueError(f"Unsupported format: {report.format}")
            
            # Update report record
            file_size = os.path.getsize(file_path)
            report.file_path = file_path
            report.file_size = file_size
            report.status = ReportStatus.READY
            report.completed_at = datetime.utcnow()
            report.generation_duration_seconds = (datetime.utcnow() - report.updated_at).total_seconds()
            
            # Try to get page count for PDF
            if report.format == ReportFormat.PDF:
                report.page_count = self._get_pdf_page_count(file_path)
            
            db.commit()
            return file_path
            
        except Exception as e:
            report.status = ReportStatus.FAILED
            report.generation_error = str(e)
            db.commit()
            raise
    
    def _collect_report_data(self, report: Report, db: Session) -> 'ReportData':
        """Collect all data needed for report"""
        # Get scans
        scans = []
        if report.scan_ids:
            scans = db.query(Scan).filter(Scan.id.in_(report.scan_ids)).all()
        
        # Get findings
        findings = []
        if report.finding_ids:
            findings = db.query(Finding).filter(Finding.id.in_(report.finding_ids)).all()
        elif report.scan_ids:
            findings = db.query(Finding).filter(Finding.scan_id.in_(report.scan_ids)).all()
        
        # Get assets
        assets = []
        if report.asset_ids:
            assets = db.query(Asset).filter(Asset.id.in_(report.asset_ids)).all()
        elif report.scan_ids:
            asset_ids = set()
            for scan in scans:
                if scan.asset_id:
                    asset_ids.add(scan.asset_id)
            if asset_ids:
                assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
        
        # Apply filters
        findings = self._apply_filters(findings, report)
        
        # Calculate stats
        stats = {
            'total_findings': len(findings),
            'critical': sum(1 for f in findings if f.severity.value == 'critical'),
            'high': sum(1 for f in findings if f.severity.value == 'high'),
            'medium': sum(1 for f in findings if f.severity.value == 'medium'),
            'low': sum(1 for f in findings if f.severity.value == 'low'),
            'info': sum(1 for f in findings if f.severity.value == 'info'),
            'open': sum(1 for f in findings if f.status.value == 'open'),
            'verified': sum(1 for f in findings if f.status.value == 'verified'),
            'fixed': sum(1 for f in findings if f.status.value == 'fixed'),
            'false_positive': sum(1 for f in findings if f.status.value == 'false_positive'),
            'total_scans': len(scans),
            'total_assets': len(assets),
        }
        
        # Get workspace
        workspace = scans[0].workspace if scans else (assets[0].workspace if assets else None)
        
        return ReportData(
            title=report.title,
            description=report.description,
            workspace_name=workspace.name if workspace else "Unknown",
            generated_at=datetime.utcnow(),
            generated_by="System",
            scans=[self._scan_to_dict(s) for s in scans],
            findings=[self._finding_to_dict(f) for f in findings],
            assets=[self._asset_to_dict(a) for a in assets],
            stats=stats,
            compliance_frameworks=report.compliance_frameworks or [],
            compliance_mapping=report.compliance_mapping or {},
            branding=report.template.branding if report.template else {},
        )
    
    def _apply_filters(self, findings: List[Finding], report: Report) -> List[Finding]:
        """Apply severity and status filters"""
        filtered = findings
        
        if report.severity_filter:
            filtered = [f for f in filtered if f.severity.value in report.severity_filter]
        
        if report.status_filter:
            filtered = [f for f in filtered if f.status.value in report.status_filter]
        
        if report.date_range:
            start = report.date_range.get('start')
            end = report.date_range.get('end')
            if start:
                filtered = [f for f in filtered if f.created_at >= start]
            if end:
                filtered = [f for f in filtered if f.created_at <= end]
        
        return filtered
    
    def _scan_to_dict(self, scan: Scan) -> Dict:
        return {
            'id': str(scan.id),
            'name': scan.name,
            'type': scan.type.value if hasattr(scan.type, 'value') else scan.type,
            'target': scan.target,
            'status': scan.status.value if hasattr(scan.status, 'value') else scan.status,
            'progress': scan.progress,
            'findings_count': scan.findings_count,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'duration_seconds': scan.duration_seconds,
        }
    
    def _finding_to_dict(self, finding: Finding) -> Dict:
        return {
            'id': str(finding.id),
            'title': finding.title,
            'description': finding.description,
            'severity': finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
            'status': finding.status.value if hasattr(finding.status, 'value') else finding.status,
            'target_url': finding.target_url,
            'parameter': finding.parameter,
            'method': finding.method,
            'path': finding.path,
            'cwe_id': finding.cwe_id,
            'cve_ids': finding.cve_ids,
            'cvss_score': finding.cvss_score,
            'cvss_vector': finding.cvss_vector,
            'source_scanner': finding.source_scanner,
            'source_rule_id': finding.source_rule_id,
            'remediation': finding.remediation,
            'created_at': finding.created_at.isoformat() if finding.created_at else None,
            'compliance_mappings': finding.compliance_mappings,
        }
    
    def _asset_to_dict(self, asset: Asset) -> Dict:
        return {
            'id': str(asset.id),
            'target': asset.target,
            'type': asset.type.value if hasattr(asset.type, 'value') else asset.type,
            'risk_level': asset.risk_level.value if hasattr(asset.risk_level, 'value') else asset.risk_level,
            'vulnerabilities_count': asset.vulnerabilities_count,
        }
    
    # ==================== PDF Generation ====================
    
    def _generate_pdf(self, data: 'ReportData', report: Report) -> str:
        """Generate PDF report using ReportLab"""
        file_path = self.reports_dir / f"report_{report.id}.pdf"
        
        doc = SimpleDocTemplate(
            str(file_path),
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm,
        )
        
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            textColor=HexColor(self._get_brand_color(data.branding, 'primary', '#1e3a8a')),
            spaceAfter=6,
            alignment=TA_CENTER,
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Normal'],
            fontSize=12,
            textColor=HexColor('#64748b'),
            spaceAfter=20,
            alignment=TA_CENTER,
        )
        
        heading1_style = ParagraphStyle(
            'Heading1Custom',
            parent=styles['Heading1'],
            fontSize=16,
            textColor=HexColor(self._get_brand_color(data.branding, 'primary', '#1e3a8a')),
            spaceBefore=16,
            spaceAfter=8,
        )
        
        heading2_style = ParagraphStyle(
            'Heading2Custom',
            parent=styles['Heading2'],
            fontSize=13,
            textColor=HexColor('#334155'),
            spaceBefore=12,
            spaceAfter=6,
        )
        
        body_style = ParagraphStyle(
            'BodyCustom',
            parent=styles['Normal'],
            fontSize=10,
            leading=14,
            spaceAfter=6,
            alignment=TA_JUSTIFY,
        )
        
        # Cover page
        if data.branding.get('logo_path'):
            try:
                logo = Image(data.branding['logo_path'], width=3*inch, height=1.5*inch)
                logo.hAlign = 'CENTER'
                story.append(logo)
                story.append(Spacer(1, 20))
            except:
                pass
        
        story.append(Paragraph(data.title, title_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph(data.description or "Security Assessment Report", subtitle_style))
        story.append(Spacer(1, 30))
        
        # Metadata table
        meta_data = [
            ['Workspace', data.workspace_name],
            ['Generated', data.generated_at.strftime('%Y-%m-%d %H:%M UTC')],
            ['Generated By', data.generated_by],
            ['Report Format', 'PDF'],
            ['Classification', data.branding.get('classification', 'CONFIDENTIAL')],
        ]
        
        meta_table = Table(meta_data, colWidths=[4*cm, 12*cm])
        meta_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), HexColor('#475569')),
            ('TEXTCOLOR', (1, 0), (1, -1), HexColor('#1e293b')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8fafc')),
        ]))
        story.append(meta_table)
        story.append(PageBreak())
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading1_style))
        story.append(Paragraph(
            f"This report presents the results of security assessments conducted on {data.workspace_name}. "
            f"A total of {data.stats['total_findings']} vulnerabilities were identified across "
            f"{data.stats['total_scans']} scans and {data.stats['total_assets']} assets.",
            body_style
        ))
        story.append(Spacer(1, 12))
        
        # Risk Summary Table
        risk_data = [
            ['Risk Level', 'Count', 'Percentage'],
            ['Critical', str(data.stats['critical']), f"{data.stats['critical']/max(1,data.stats['total_findings'])*100:.1f}%"],
            ['High', str(data.stats['high']), f"{data.stats['high']/max(1,data.stats['total_findings'])*100:.1f}%"],
            ['Medium', str(data.stats['medium']), f"{data.stats['medium']/max(1,data.stats['total_findings'])*100:.1f}%"],
            ['Low', str(data.stats['low']), f"{data.stats['low']/max(1,data.stats['total_findings'])*100:.1f}%"],
            ['Info', str(data.stats['info']), f"{data.stats['info']/max(1,data.stats['total_findings'])*100:.1f}%"],
            ['Total', str(data.stats['total_findings']), '100%'],
        ]
        
        risk_table = Table(risk_data, colWidths=[4*cm, 3*cm, 3*cm])
        risk_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1e3a8a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
            ('TEXTCOLOR', (0, 1), (0, -1), HexColor('#1e293b')),
            ('TEXTCOLOR', (1, 1), (1, -1), HexColor('#1e293b')),
            ('TEXTCOLOR', (2, 1), (2, -1), HexColor('#64748b')),
            ('BACKGROUND', (0, 1), (-1, 1), HexColor('#fef2f2')),  # Critical
            ('BACKGROUND', (0, 2), (-1, 2), HexColor('#fff7ed')),  # High
            ('BACKGROUND', (0, 3), (-1, 3), HexColor('#fefce8')),  # Medium
            ('BACKGROUND', (0, 4), (-1, 4), HexColor('#f0fdf4')),  # Low
            ('BACKGROUND', (0, 5), (-1, 5), HexColor('#f1f5f9')),  # Info
            ('BACKGROUND', (0, -1), (-1, -1), HexColor('#e2e8f0')),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(risk_table)
        story.append(PageBreak())
        
        # Findings by Severity
        for severity_name in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            severity_findings = [f for f in data.findings 
                               if f['severity'].lower() == severity_name.lower()]
            if not severity_findings:
                continue
            
            story.append(Paragraph(f"{severity_name} Severity Findings", heading1_style))
            
            for finding in severity_findings:
                story.append(Paragraph(finding['title'], heading2_style))
                story.append(Paragraph(finding['description'], body_style))
                
                # Finding details table
                detail_data = [
                    ['Attribute', 'Value'],
                    ['Severity', finding['severity']],
                    ['Status', finding['status']],
                    ['Target', finding.get('target_url', 'N/A')],
                    ['Parameter', finding.get('parameter', 'N/A')],
                    ['Method', finding.get('method', 'N/A')],
                    ['CWE', finding.get('cwe_id', 'N/A')],
                    ['CVSS', str(finding.get('cvss_score', 'N/A'))],
                    ['Source', finding.get('source_scanner', 'N/A')],
                ]
                
                if finding.get('cve_ids'):
                    detail_data.append(['CVE IDs', ', '.join(finding['cve_ids'])])
                
                detail_table = Table(detail_data, colWidths=[4*cm, 12*cm])
                detail_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('BACKGROUND', (0, 0), (0, -1), HexColor('#f8fafc')),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ]))
                story.append(detail_table)
                story.append(Spacer(1, 8))
                
                if finding.get('remediation'):
                    story.append(Paragraph("<b>Remediation:</b>", body_style))
                    story.append(Paragraph(finding['remediation'], body_style))
                
                story.append(Spacer(1, 12))
            
            story.append(PageBreak())
        
        # Compliance Mapping
        if data.compliance_mapping:
            story.append(Paragraph("Compliance Mapping", heading1_style))
            for framework, mappings in data.compliance_mapping.items():
                story.append(Paragraph(framework, heading2_style))
                # Add mapping table
                map_data = [['Requirement', 'Finding', 'Status']]
                for req, finding_ids in mappings.items():
                    for fid in finding_ids:
                        f = next((f for f in data.findings if f['id'] == fid), None)
                        if f:
                            map_data.append([req, f['title'], f['status']])
                
                if len(map_data) > 1:
                    comp_table = Table(map_data, colWidths=[5*cm, 8*cm, 3*cm])
                    comp_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1e3a8a')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#e2e8f0')),
                        ('TOPPADDING', (0, 0), (-1, -1), 4),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ]))
                    story.append(comp_table)
                    story.append(Spacer(1, 12))
        
        # Footer
        story.append(Spacer(1, 40))
        footer_text = data.branding.get('footer_text', 
            "CONFIDENTIAL - For authorized recipients only. This report contains sensitive security information.")
        story.append(Paragraph(footer_text, ParagraphStyle(
            'Footer', parent=styles['Normal'], fontSize=8, 
            textColor=HexColor('#94a3b8'), alignment=TA_CENTER
        )))
        
        # Build
        doc.build(story)
        return str(self.reports_dir / f"report_{uuid.uuid4().hex[:8]}.pdf")
    
    # ==================== DOCX Generation ====================
    
    def _generate_docx(self, data: 'ReportData', report: Report) -> str:
        """Generate DOCX report using python-docx"""
        doc = Document()
        
        # Styles
        style = doc.styles['Normal']
        font = style.font
        font.name = 'Calibri'
        font.size = Pt(11)
        
        # Title
        title = doc.add_heading(data.title, 0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        
        # Subtitle
        subtitle = doc.add_paragraph(data.description or "Security Assessment Report")
        subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
        subtitle.runs[0].font.color.rgb = RGBColor(0x64, 0x74, 0x8b)
        subtitle.runs[0].font.size = Pt(12)
        
        doc.add_paragraph()
        
        # Metadata table
        meta_table = doc.add_table(rows=5, cols=2)
        meta_table.style = 'Light Grid Accent 1'
        meta_data = [
            ['Workspace', data.workspace_name],
            ['Generated', data.generated_at.strftime('%Y-%m-%d %H:%M UTC')],
            ['Generated By', data.generated_by],
            ['Report Format', 'DOCX'],
            ['Classification', data.branding.get('classification', 'CONFIDENTIAL')],
        ]
        for i, (key, value) in enumerate(meta_data):
            meta_table.rows[i].cells[0].text = key
            meta_table.rows[i].cells[1].text = value
            # Bold the key
            for paragraph in meta_table.rows[i].cells[0].paragraphs:
                for run in paragraph.runs:
                    run.bold = True
        
        doc.add_page_break()
        
        # Executive Summary
        doc.add_heading('Executive Summary', level=1)
        doc.add_paragraph(
            f"This report presents the results of security assessments conducted on {data.workspace_name}. "
            f"A total of {data.stats['total_findings']} vulnerabilities were identified across "
            f"{data.stats['total_scans']} scans and {data.stats['total_assets']} assets."
        )
        
        # Risk Summary
        doc.add_heading('Risk Summary', level=1)
        risk_table = doc.add_table(rows=7, cols=3)
        risk_table.style = 'Light Grid Accent 1'
        risk_headers = ['Risk Level', 'Count', 'Percentage']
        for i, header in enumerate(risk_headers):
            risk_table.rows[0].cells[i].text = header
            for paragraph in risk_table.rows[0].cells[i].paragraphs:
                for run in paragraph.runs:
                    run.bold = True
        
        risk_data = [
            ('Critical', data.stats['critical']),
            ('High', data.stats['high']),
            ('Medium', data.stats['medium']),
            ('Low', data.stats['low']),
            ('Info', data.stats['info']),
            ('Total', data.stats['total_findings']),
        ]
        for i, (level, count) in enumerate(risk_data):
            risk_table.rows[i+1].cells[0].text = level
            risk_table.rows[i+1].cells[1].text = str(count)
            risk_table.rows[i+1].cells[2].text = f"{count/max(1,data.stats['total_findings'])*100:.1f}%"
        
        doc.add_page_break()
        
        # Findings by Severity
        for severity_name in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            severity_findings = [f for f in data.findings 
                               if f['severity'].lower() == severity_name.lower()]
            if not severity_findings:
                continue
            
            doc.add_heading(f'{severity_name} Severity Findings', level=1)
            
            for finding in severity_findings:
                doc.add_heading(finding['title'], level=2)
                doc.add_paragraph(finding['description'])
                
                # Details table
                detail_table = doc.add_table(rows=10, cols=2)
                detail_table.style = 'Light Grid Accent 1'
                details = [
                    ('Severity', finding['severity']),
                    ('Status', finding['status']),
                    ('Target', finding.get('target_url', 'N/A')),
                    ('Parameter', finding.get('parameter', 'N/A')),
                    ('Method', finding.get('method', 'N/A')),
                    ('CWE', finding.get('cwe_id', 'N/A')),
                    ('CVSS', str(finding.get('cvss_score', 'N/A'))),
                    ('Source', finding.get('source_scanner', 'N/A')),
                ]
                if finding.get('cve_ids'):
                    details.append(('CVE IDs', ', '.join(finding['cve_ids'])))
                
                for i, (key, value) in enumerate(details):
                    detail_table.rows[i].cells[0].text = key
                    detail_table.rows[i].cells[1].text = value
                    for paragraph in detail_table.rows[i].cells[0].paragraphs:
                        for run in paragraph.runs:
                            run.bold = True
                
                if finding.get('remediation'):
                    doc.add_paragraph()
                    p = doc.add_paragraph()
                    run = p.add_run('Remediation: ')
                    run.bold = True
                    p.add_run(finding['remediation'])
                
                doc.add_paragraph()
        
        # Save
        file_path = self.reports_dir / f"report_{report.id}.docx"
        doc.save(str(file_path))
        return str(file_path)
    
    # ==================== HTML Generation ====================
    
    def _generate_html(self, data: 'ReportData', report: Report) -> str:
        """Generate HTML report using Jinja2"""
        template = self.jinja_env.get_template('report.html')
        
        html = template.render(
            data=data,
            report=report,
            generated_at=data.generated_at.strftime('%Y-%m-%d %H:%M:%S'),
        )
        
        file_path = self.reports_dir / f"report_{report.id}.html"
        with open(file_path, 'w') as f:
            f.write(html)
        return str(file_path)
    
    # ==================== CSV Generation ====================
    
    def _generate_csv(self, data: 'ReportData', report: Report) -> str:
        """Generate CSV report with findings"""
        file_path = self.reports_dir / f"report_{report.id}.csv"
        
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'ID', 'Title', 'Severity', 'Status', 'Target URL', 'Parameter',
                'Method', 'Path', 'CWE', 'CVE IDs', 'CVSS Score', 'CVSS Vector',
                'Source Scanner', 'Source Rule', 'Remediation', 'Created At'
            ])
            
            # Findings
            for finding in data.findings:
                writer.writerow([
                    finding['id'],
                    finding['title'],
                    finding['severity'],
                    finding['status'],
                    finding.get('target_url', ''),
                    finding.get('parameter', ''),
                    finding.get('method', ''),
                    finding.get('path', ''),
                    finding.get('cwe_id', ''),
                    ', '.join(finding.get('cve_ids', [])),
                    finding.get('cvss_score', ''),
                    finding.get('cvss_vector', ''),
                    finding.get('source_scanner', ''),
                    finding.get('source_rule_id', ''),
                    finding.get('remediation', ''),
                    finding.get('created_at', ''),
                ])
        
        return str(file_path)
    
    # ==================== JSON Generation ====================
    
    def _generate_json(self, data: 'ReportData', report: Report) -> str:
        """Generate JSON report"""
        file_path = self.reports_dir / f"report_{report.id}.json"
        
        output = {
            'report': {
                'id': str(report.id),
                'title': data.title,
                'description': data.description,
                'workspace': data.workspace_name,
                'generated_at': data.generated_at.isoformat(),
                'generated_by': data.generated_by,
                'format': 'JSON',
            },
            'stats': data.stats,
            'scans': data.scans,
            'findings': data.findings,
            'assets': data.assets,
            'compliance': {
                'frameworks': data.compliance_frameworks,
                'mapping': data.compliance_mapping,
            },
        }
        
        with open(file_path, 'w') as f:
            json.dump(output, f, indent=2, default=str)
        
        return str(file_path)
    
    # ==================== Helpers ====================
    
    def _get_brand_color(self, branding: Dict, key: str, default: str) -> str:
        return branding.get(key, default)
    
    def _get_pdf_page_count(self, file_path: str) -> int:
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(file_path)
            return len(reader.pages)
        except:
            return 0


# Celery task for report generation
from celery import shared_task

@shared_task(bind=True, max_retries=1)
def generate_report_task(self, report_id: str):
    """Celery task to generate report"""
    from core.database import get_sync_db
    from models.report import Report
    
    db: Session = next(get_sync_db())
    try:
        report = db.query(Report).filter(Report.id == report_id).first()
        if not report:
            return {'error': 'Report not found'}
        
        generator = ReportGenerator()
        file_path = generator.generate(report, db)
        
        return {'status': 'completed', 'file_path': file_path}
    except Exception as e:
        report = db.query(Report).filter(Report.id == report_id).first()
        if report:
            report.status = ReportStatus.FAILED
            report.generation_error = str(e)
            db.commit()
        raise