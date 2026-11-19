from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from uuid import UUID
from io import BytesIO
import json
import os
import os.path

from docx import Document
from docx.shared import Inches, Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

from weasyprint import HTML, CSS
from jinja2 import Environment, FileSystemLoader, select_autoescape

from models.scan import Scan, ScanStatus, ScanType
from models.finding import Finding, FindingStatus
from models.asset import Asset
from models.workspace import Workspace
from models.report import Report, ReportTemplate, ReportTemplateType


class ReportService:
    def __init__(self, templates_dir: str = "/app/templates"):
        self.templates_dir = templates_dir
        self.jinja_env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(['html', 'xml']),
        )

    def _severity_color(self, severity: str) -> str:
        colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#16a34a",
            "info": "#2563eb",
        }
        return colors.get(severity.lower(), "#6b7280")

    def _severity_order(self, severity: str) -> int:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(severity.lower(), 5)

    def generate_docx(self, report: Report, workspace: Workspace, scans: List[Scan], findings: List[Finding], assets: List[Asset]) -> bytes:
        doc = Document()

        # Style adjustments
        style = doc.styles['Normal']
        font = style.font
        font.name = 'Calibri'
        font.size = Pt(11)
        style.paragraph_format.space_after = Pt(6)

        # Title
        title = doc.add_heading(report.title or f"Pentest Report - {workspace.name}", level=0)
        title.alignment = WD_ALIGN_PARAGRAPH.CENTER

        # Metadata table
        meta_table = doc.add_table(rows=6, cols=2)
        meta_table.style = 'Light Grid Accent 1'
        meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER

        meta_data = [
            ("Workspace", workspace.name),
            ("Report Type", report.template.type.value if report.template and report.template.type else "Custom"),
            ("Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")),
            ("Period", f"{report.date_range.get('start', 'N/A')} to {report.date_range.get('end', 'N/A')}"),
            ("Scans Included", str(len(scans))),
            ("Total Findings", str(len(findings))),
        ]

        for i, (key, value) in enumerate(meta_data):
            meta_table.rows[i].cells[0].text = key
            meta_table.rows[i].cells[1].text = value
            for cell in meta_table.rows[i].cells:
                for paragraph in cell.paragraphs:
                    paragraph.style = doc.styles['Normal']

        doc.add_paragraph()

        # Executive Summary
        doc.add_heading("Executive Summary", level=1)
        if report.description:
            doc.add_paragraph(report.description)
        else:
            critical = sum(1 for f in findings if f.severity == "critical")
            high = sum(1 for f in findings if f.severity == "high")
            medium = sum(1 for f in findings if f.severity == "medium")
            low = sum(1 for f in findings if f.severity == "low")

            summary_text = (
                f"This report summarizes the results of {len(scans)} security scans "
                f"conducted against {len(assets)} assets. "
                f"A total of {len(findings)} findings were identified: "
                f"{critical} critical, {high} high, {medium} medium, and {low} low severity. "
            )
            if critical > 0:
                summary_text += "Immediate attention is required for critical findings."
            elif high > 0:
                summary_text += "High severity findings should be addressed promptly."
            doc.add_paragraph(summary_text)

        doc.add_paragraph()

        # Findings by Severity
        doc.add_heading("Findings by Severity", level=1)

        severity_table = doc.add_table(rows=1, cols=4)
        severity_table.style = 'Light Grid Accent 1'
        hdr = severity_table.rows[0].cells
        hdr[0].text = "Severity"
        hdr[1].text = "Count"
        hdr[2].text = "Percentage"
        hdr[3].text = "Trend"

        severity_counts = {}
        for f in findings:
            sev = f.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        total = len(findings)
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            pct = f"{(count/total*100):.1f}%" if total > 0 else "0%"
            row = severity_table.add_row().cells
            row[0].text = sev.capitalize()
            row[1].text = str(count)
            row[2].text = pct
            row[3].text = "—"

            # Color the severity cell
            shading = OxmlElement('w:shd')
            shading.set(qn('w:fill'), self._severity_color(sev).replace('#', ''))
            shading.set(qn('w:val'), 'clear')
            row[0]._tc.get_or_add_tcPr().append(shading)

        doc.add_paragraph()

        # Findings Detail
        doc.add_heading("Findings Detail", level=1)

        if not findings:
            doc.add_paragraph("No findings were identified in this reporting period.")
        else:
            # Sort findings by severity
            sorted_findings = sorted(findings, key=lambda f: self._severity_order(f.severity))

            for finding in sorted_findings:
                doc.add_heading(finding.title, level=2)

                detail_table = doc.add_table(rows=6, cols=2)
                detail_table.style = 'Light Grid Accent 1'

                detail_data = [
                    ("Severity", finding.severity.capitalize()),
                    ("Status", finding.status.value if finding.status else "Open"),
                    ("Target", finding.target_url or "N/A"),
                    ("Parameter", finding.parameter or "N/A"),
                    ("Scanner", finding.source_scanner or "N/A"),
                    ("CWE", finding.cwe_id or "N/A"),
                ]

                for i, (key, value) in enumerate(detail_data):
                    detail_table.rows[i].cells[0].text = key
                    detail_table.rows[i].cells[1].text = value

                # Color severity row
                sev_cell = detail_table.rows[0].cells[1]
                shading = OxmlElement('w:shd')
                shading.set(qn('w:fill'), self._severity_color(finding.severity).replace('#', ''))
                shading.set(qn('w:val'), 'clear')
                sev_cell._tc.get_or_add_tcPr().append(shading)

                if finding.description:
                    doc.add_paragraph()
                    doc.add_paragraph("Description:")
                    doc.add_paragraph(finding.description)

                if finding.remediation:
                    doc.add_paragraph()
                    doc.add_paragraph("Remediation:")
                    doc.add_paragraph(finding.remediation)

                if finding.cve_ids:
                    doc.add_paragraph()
                    doc.add_paragraph("CVE References:")
                    for cve in finding.cve_ids:
                        doc.add_paragraph(f"• {cve}", style='List Bullet')

                doc.add_paragraph()

        # Scans Summary
        doc.add_heading("Scans Summary", level=1)
        scans_table = doc.add_table(rows=1, cols=5)
        scans_table.style = 'Light Grid Accent 1'
        hdr = scans_table.rows[0].cells
        hdr[0].text = "Scan Name"
        hdr[1].text = "Type"
        hdr[2].text = "Target"
        hdr[3].text = "Status"
        hdr[4].text = "Findings"

        for scan in scans:
            row = scans_table.add_row().cells
            row[0].text = scan.name or "Unnamed"
            row[1].text = scan.type.value if scan.type else "N/A"
            row[2].text = scan.target
            row[3].text = scan.status.value if scan.status else "N/A"
            row[4].text = str(scan.findings_count or 0)

        doc.add_paragraph()

        # Assets Summary
        doc.add_heading("Assets Summary", level=1)
        assets_table = doc.add_table(rows=1, cols=4)
        assets_table.style = 'Light Grid Accent 1'
        hdr = assets_table.rows[0].cells
        hdr[0].text = "Asset"
        hdr[1].text = "Type"
        hdr[2].text = "Risk Level"
        hdr[3].text = "Scans"

        for asset in assets:
            row = assets_table.add_row().cells
            row[0].text = asset.target
            row[1].text = asset.type.value if asset.type else "N/A"
            row[2].text = asset.risk_level.value if asset.risk_level else "N/A"
            row[3].text = str(asset.total_scans or 0)

        # Save to bytes
        buffer = BytesIO()
        doc.save(buffer)
        buffer.seek(0)
        return buffer.read()

    def generate_pdf(self, report: Report, workspace: Workspace, scans: List[Scan], findings: List[Finding], assets: List[Asset]) -> bytes:
        template = self.jinja_env.get_template("report.html")

        # Prepare data for template
        severity_counts = {}
        for f in findings:
            sev = f.severity.lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        sorted_findings = sorted(findings, key=lambda f: self._severity_order(f.severity))

        html = template.render(
            report=report,
            workspace=workspace,
            scans=scans,
            findings=sorted_findings,
            assets=assets,
            severity_counts=severity_counts,
            total_findings=len(findings),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            severity_color=self._severity_color,
        )

        # Generate PDF
        css = CSS(string="""
            @page { size: A4; margin: 2cm; }
            body { font-family: 'DejaVu Sans', sans-serif; font-size: 11pt; line-height: 1.5; color: #1f2937; }
            h1 { color: #1e40af; border-bottom: 2px solid #1e40af; padding-bottom: 0.3rem; }
            h2 { color: #3730a3; margin-top: 1.5rem; }
            h3 { color: #4338ca; }
            table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 10pt; }
            th, td { border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; }
            th { background-color: #f3f4f6; font-weight: 600; }
            tr:nth-child(even) { background-color: #f9fafb; }
            .severity-critical { background-color: #fef2f2; color: #dc2626; font-weight: bold; }
            .severity-high { background-color: #fff7ed; color: #ea580c; font-weight: bold; }
            .severity-medium { background-color: #fefce8; color: #ca8a04; font-weight: bold; }
            .severity-low { background-color: #f0fdf4; color: #16a34a; font-weight: bold; }
            .severity-info { background-color: #eff6ff; color: #2563eb; font-weight: bold; }
            .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
            .meta-table td:first-child { font-weight: 600; width: 30%; }
            .finding-card { border: 1px solid #e5e7eb; border-radius: 0.5rem; padding: 1rem; margin: 1rem 0; page-break-inside: avoid; }
            .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
        """)

        pdf_bytes = HTML(string=html).write_pdf(stylesheets=[css])
        return pdf_bytes


async def generate_report(
    report: Report,
    workspace: Workspace,
    scans: List[Scan],
    findings: List[Finding],
    assets: List[Asset],
    format: str = "pdf",
) -> bytes:
    # Use the project's templates directory
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    templates_dir = os.path.join(base_dir, "templates")
    service = ReportService(templates_dir)

    if format.lower() == "docx":
        return service.generate_docx(report, workspace, scans, findings, assets)
    else:
        return service.generate_pdf(report, workspace, scans, findings, assets)