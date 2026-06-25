# ... after risk scorer ...
from modules.report_generator import ReportOrchestrator
report_gen = ReportOrchestrator()
scan_context = report_gen.generate(scan_context)
print(f"\n[Module 4] Report generated: {scan_context['report']['generated_file']}")