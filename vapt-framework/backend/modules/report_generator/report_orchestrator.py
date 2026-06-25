"""
Report Generator Orchestrator.
"""

import logging
from typing import Optional, Dict, Any
from pathlib import Path

from .report_builder import ReportBuilder
from .html_templates import get_report_template
from .pdf_generator import PDFGenerator

logger = logging.getLogger(__name__)


class ReportOrchestrator:
    """Orchestrates report generation from scan_context."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, scan_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate report and update scan_context.

        Args:
            scan_context: Full pipeline results.

        Returns:
            Updated scan_context with report paths.
        """
        # Build report data
        report = ReportBuilder.build(scan_context)
        report_dict = report.to_dict()

        # Generate HTML
        html_content = get_report_template(report_dict)

        # Generate PDF (or HTML fallback)
        output_path = self.output_dir / f"vapt_report_{report.report_id}.pdf"
        generated_path = PDFGenerator.generate(html_content, output_path)

        # Store in scan_context
        scan_context["report"] = {
            "report_id": report.report_id,
            "html_content": html_content,
            "generated_file": generated_path,
            "report_data": report_dict
        }
        scan_context["modules_executed"] = scan_context.get("modules_executed", []) + ["report_generator"]

        logger.info(f"Report generated: {generated_path}")
        return scan_context