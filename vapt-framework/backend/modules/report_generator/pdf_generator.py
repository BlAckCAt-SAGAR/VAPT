"""
PDF generation using weasyprint or fallback to HTML only.
"""

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class PDFGenerator:
    """Converts HTML report to PDF."""

    @staticmethod
    def generate(html_content: str, output_path: Optional[Path] = None) -> Optional[str]:
        """
        Convert HTML to PDF. Uses weasyprint if available, else saves HTML.

        Args:
            html_content: Complete HTML string.
            output_path: Where to save the PDF. Defaults to 'reports/' directory.

        Returns:
            Path to the generated file, or None on failure.
        """
        if output_path is None:
            output_path = Path("reports") / f"vapt_report_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Try weasyprint
        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(str(output_path))
            logger.info(f"PDF generated: {output_path}")
            return str(output_path)
        except ImportError:
            logger.warning("weasyprint not installed. Saving as HTML instead.")
            html_path = output_path.with_suffix('.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report saved: {html_path}")
            return str(html_path)
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            # Fallback to HTML
            html_path = output_path.with_suffix('.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return str(html_path)