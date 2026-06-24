"""
Full VAPT Pipeline Demo: Recon → Scanner → Risk Scorer
"""
import asyncio
import json
import time
from modules.recon import ReconOrchestrator
from modules.scanner import ScanOrchestrator
from modules.risk_scorer import RiskOrchestrator

async def run_full_pipeline(target: str = "example.com"):
    print("=" * 70)
    print("VAPT FRAMEWORK - FULL AUTOMATED PIPELINE")
    print("=" * 70)
    overall_start = time.time()

    # --------------------- Module 1: Recon ---------------------
    print("\n[Module 1] Reconnaissance...")
    recon = ReconOrchestrator()
    scan_context = await recon.run(target)
    print(f"  → Found {len(scan_context['recon_data'].get('subdomains', []))} subdomains")
    print(f"  → Resolved IPs: {scan_context['recon_data']['resolved_ips'][:2]}...")

    # --------------------- Module 2: Scanner -------------------
    print("\n[Module 2] Unified Scanner...")
    scanner = ScanOrchestrator()
    scan_context = await scanner.run(scan_context)
    scanner_results = scan_context.get("scanner_results", {})
    http = scanner_results.get("http_finding", {})
    print(f"  → HTTP status: {http.get('status_code')}")
    print(f"  → Header issues: {len(scanner_results.get('header_issues', []))}")
    print(f"  → Open ports: {len(scanner_results.get('open_ports', []))}")
    print(f"  → CVEs matched: {len(scanner_results.get('cve_matches', []))}")

    # --------------------- Module 3: Risk Scorer ---------------
    print("\n[Module 3] Risk Scoring Engine...")
    risk = RiskOrchestrator(config={"public_facing": True})
    scan_context = risk.run(scan_context)
    risk_report = scan_context.get("risk_report", {})

    # --------------------- Final Summary -----------------------
    overall_end = time.time()
    print("\n" + "=" * 70)
    print("FINAL RISK REPORT")
    print("=" * 70)
    print(f"Target: {risk_report.get('target')}")
    print(f"Overall Score: {risk_report.get('overall_score')}/100  Grade: {risk_report.get('grade')}")
    print(f"Grade Description: {risk_report.get('grade_description')}")
    summary = risk_report.get("summary", {})
    print(f"Findings: {summary.get('total_findings')} "
          f"(C:{summary.get('critical_count')} H:{summary.get('high_count')} "
          f"M:{summary.get('medium_count')} L:{summary.get('low_count')})")
    print(f"Top Recommendations:")
    for i, rec in enumerate(risk_report.get("recommendations", []), 1):
        print(f"  {i}. {rec}")

    print(f"\nPipeline completed in {overall_end - overall_start:.2f} seconds")
    print(f"Modules executed: {scan_context.get('modules_executed', [])}")

    # Save full context
    with open("full_scan_context.json", "w") as f:
        json.dump(scan_context, f, indent=2, default=str)
    print("\nFull context saved to full_scan_context.json")

if __name__ == "__main__":
    asyncio.run(run_full_pipeline("example.com"))