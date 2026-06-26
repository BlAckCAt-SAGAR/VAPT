"""
Celery task for orchestrating VAPT scans.
"""

from celery import Task
from celery.result import AsyncResult
from typing import Dict, Any, Optional
import asyncio
import json
import os
from datetime import datetime, timezone

from tasks.celery_app import celery_app


# In-memory store for scan results (replace with Redis in production)
_scan_results: Dict[str, Dict[str, Any]] = {}


class ScanTask(Task):
    """Custom Celery task with progress tracking."""
    
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Handle task failure gracefully."""
        if task_id in _scan_results:
            _scan_results[task_id]["status"] = "failed"
            _scan_results[task_id]["errors"].append(str(exc))


@celery_app.task(bind=True, base=ScanTask, name="run_vapt_scan")
def run_vapt_scan(self, target: str, scan_type: str = "full") -> Dict[str, Any]:
    """
    Execute the full VAPT pipeline.
    
    Args:
        target: Domain or IP to scan.
        scan_type: 'full', 'quick', or 'recon-only'
        
    Returns:
        Complete scan_context with results.
    """
    task_id = self.request.id
    
    # Initialize scan state
    _scan_results[task_id] = {
        "scan_id": task_id,
        "target": target,
        "status": "running",
        "progress": 0,
        "current_module": "",
        "modules_executed": [],
        "errors": [],
        "started_at": datetime.now(timezone.utc).isoformat()
    }
    
    def progress_callback(module: str, percent: float, message: str):
        """Update scan progress."""
        _scan_results[task_id].update({
            "progress": percent,
            "current_module": module,
            "message": message
        })
        self.update_state(state="PROGRESS", meta={"progress": percent, "module": module})
    
    try:
        # Run the async pipeline in a sync context
        scan_context = asyncio.run(_run_pipeline(target, scan_type, progress_callback))
        
        _scan_results[task_id].update({
            "status": "completed",
            "progress": 100,
            "modules_executed": scan_context.get("modules_executed", []),
            "result_summary": {
                "score": scan_context.get("risk_report", {}).get("overall_score"),
                "grade": scan_context.get("risk_report", {}).get("grade"),
                "findings": scan_context.get("risk_report", {}).get("summary", {})
            },
            "report_path": scan_context.get("report", {}).get("generated_file"),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "execution_time": scan_context.get("execution_time_seconds")
        })
        
        return scan_context
        
    except Exception as e:
        _scan_results[task_id]["status"] = "failed"
        _scan_results[task_id]["errors"].append(str(e))
        raise


async def _run_pipeline(target: str, scan_type: str, progress_callback) -> Dict[str, Any]:
    """Run the VAPT pipeline asynchronously."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    
    from modules.recon import ReconOrchestrator
    from modules.scanner import ScanOrchestrator
    from modules.risk_scorer import RiskOrchestrator
    from modules.report_generator import ReportOrchestrator
    
    # Module 1: Reconnaissance
    progress_callback("recon", 5, "Starting reconnaissance")
    recon = ReconOrchestrator()
    scan_context = await recon.run(target)
    progress_callback("recon", 25, "Reconnaissance complete")
    
    # Module 2: Scanner
    if scan_type in ["full", "quick"]:
        progress_callback("scanner", 30, "Starting scan")
        scanner = ScanOrchestrator()
        scan_context = await scanner.run(scan_context)
        progress_callback("scanner", 50, "Scan complete")
    
    # Module 3: Risk Scorer
    if scan_type == "full":
        progress_callback("risk_scorer", 55, "Calculating risk score")
        risk = RiskOrchestrator(config={"public_facing": True})
        scan_context = risk.run(scan_context)
        progress_callback("risk_scorer", 75, "Risk score calculated")
    
    # Module 4: Report Generator
    progress_callback("report_generator", 80, "Generating report")
    report = ReportOrchestrator()
    scan_context = report.generate(scan_context)
    progress_callback("report_generator", 100, "Report ready")
    
    return scan_context


def get_scan_status(scan_id: str) -> Optional[Dict[str, Any]]:
    """Get the current status of a scan."""
    return _scan_results.get(scan_id)


def get_scan_report(scan_id: str, format: str = "json") -> Optional[Any]:
    """Get the scan report."""
    result = _scan_results.get(scan_id, {})
    task_result = AsyncResult(scan_id, app=celery_app)
    
    if task_result.ready() and task_result.successful():
        scan_context = task_result.result
        if format == "html":
            return {
                "content_type": "text/html",
                "content": scan_context.get("report", {}).get("html_content", "")
            }
        return scan_context
    return None


def list_scans(limit: int = 10, offset: int = 0) -> tuple:
    """List recent scans."""
    scans = list(_scan_results.values())
    scans.sort(key=lambda x: x.get("started_at", ""), reverse=True)
    return scans[offset:offset + limit], len(scans)