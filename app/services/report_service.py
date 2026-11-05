import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from app.config import settings


class ReportService:
    def __init__(self):
        self.report_dir = settings.report_path

    def generate_json_report(self, scan_data: Dict[str, Any]) -> str:
        """Formats scan data as formatted JSON string."""
        return json.dumps(scan_data, indent=2, default=str)

    def generate_pdf_report(self, scan_data: Dict[str, Any]) -> Path:
        """
        Generates a professional PDF security report.
        Saves to reports/<scan_id>.pdf and returns file Path.
        """
        scan_id = scan_data.get("scan_id", "unknown_scan")
        pdf_filename = f"report_{scan_id}.pdf"
        pdf_path = self.report_dir / pdf_filename

        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#1e293b")
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748b")
        )
        h2_style = ParagraphStyle(
            "Heading2Custom",
            parent=styles["Heading2"],
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            "BodyCustom",
            parent=styles["Normal"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155")
        )

        elements = []

        # Header Title
        elements.append(Paragraph("<b>FileScanner Security Report</b>", title_style))
        elements.append(Paragraph(f"Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Local Security Engine", subtitle_style))
        elements.append(Spacer(1, 10))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=15))

        # Status Badge Color
        status = scan_data.get("scan_status") or scan_data.get("overall_status", "UNKNOWN")
        status_color = colors.HexColor("#10b981")  # green (CLEAN)
        if status in ("MALICIOUS", "ERROR"):
            status_color = colors.HexColor("#ef4444")  # red
        elif status in ("SUSPICIOUS", "UNABLE_TO_SCAN"):
            status_color = colors.HexColor("#f59e0b")  # yellow/amber

        # Summary Table
        summary_rows = [
            [Paragraph("<b>Scan ID:</b>", body_style), Paragraph(str(scan_id), body_style)],
            [Paragraph("<b>Scan Type:</b>", body_style), Paragraph(str(scan_data.get("scan_type", "FILE")), body_style)],
            [Paragraph("<b>Target Name / URL:</b>", body_style), Paragraph(str(scan_data.get("target_name") or scan_data.get("file_name") or scan_data.get("url", "N/A")), body_style)],
            [Paragraph("<b>SHA256 Hash:</b>", body_style), Paragraph(str(scan_data.get("file_hash") or scan_data.get("sha256_hash", "N/A")), body_style)],
            [Paragraph("<b>File Size:</b>", body_style), Paragraph(f"{scan_data.get('file_size', 'N/A')} bytes" if scan_data.get("file_size") is not None else "N/A", body_style)],
            [Paragraph("<b>Final Status:</b>", body_style), Paragraph(f"<b><font color='{status_color.hexval()}'>{status}</font></b>", body_style)]
        ]

        summary_table = Table(summary_rows, colWidths=[130, 410])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#1e293b")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 15))

        # Scanner Engines Breakdown
        elements.append(Paragraph("<b>Scanner Engines Breakdown</b>", h2_style))
        scanner_results = scan_data.get("scanner_results", {})
        engine_rows = [
            [Paragraph("<b>Scanner</b>", body_style), Paragraph("<b>Status</b>", body_style), Paragraph("<b>Details / Error</b>", body_style)]
        ]

        if not scanner_results:
            engine_rows.append([Paragraph("None reported", body_style), Paragraph("N/A", body_style), Paragraph("No scanner details available", body_style)])
        else:
            for eng_name, eng_info in scanner_results.items():
                eng_status = eng_info.get("status", "UNKNOWN")
                eng_err = eng_info.get("error") or "Scan completed"
                engine_rows.append([
                    Paragraph(eng_name.upper(), body_style),
                    Paragraph(str(eng_status), body_style),
                    Paragraph(str(eng_err), body_style)
                ])

        engine_table = Table(engine_rows, colWidths=[120, 100, 320])
        engine_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(engine_table)
        elements.append(Spacer(1, 15))

        # Detected Threats Section
        elements.append(Paragraph("<b>Detected Threats & Heuristics</b>", h2_style))
        threats = scan_data.get("detected_threats", [])
        if not threats:
            elements.append(Paragraph("No threats or suspicious indicators detected. All checks passed.", body_style))
        else:
            threat_rows = [
                [
                    Paragraph("<b>Threat Name</b>", body_style),
                    Paragraph("<b>Engine</b>", body_style),
                    Paragraph("<b>Severity</b>", body_style),
                    Paragraph("<b>Category</b>", body_style),
                    Paragraph("<b>Description</b>", body_style)
                ]
            ]
            for t in threats:
                sev = t.get("severity", "MEDIUM")
                sev_color = "#ef4444" if sev in ("CRITICAL", "HIGH") else ("#f59e0b" if sev == "MEDIUM" else "#3b82f6")
                threat_rows.append([
                    Paragraph(str(t.get("threat_name", "Unknown")), body_style),
                    Paragraph(str(t.get("scanner_name", "N/A")), body_style),
                    Paragraph(f"<b><font color='{sev_color}'>{sev}</font></b>", body_style),
                    Paragraph(str(t.get("threat_category", "N/A")), body_style),
                    Paragraph(str(t.get("description", "")), body_style),
                ])

            threat_table = Table(threat_rows, colWidths=[120, 70, 70, 80, 200])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#fee2e2")),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#fca5a5")),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(threat_table)

        # Build document
        doc.build(elements)
        return pdf_path


report_service = ReportService()
