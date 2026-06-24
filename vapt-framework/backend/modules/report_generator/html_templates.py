"""
HTML/CSS templates for the security report.
Uses modern, clean design with responsive layout.
"""

CSS_STYLES = """
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 40px; border-radius: 10px; margin-bottom: 30px; }
    .header h1 { font-size: 2.5em; margin-bottom: 10px; }
    .header .subtitle { font-size: 1.2em; opacity: 0.9; }
    .score-card { background: white; border-radius: 10px; padding: 30px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .score-circle { width: 150px; height: 150px; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin: 20px auto; font-size: 3em; font-weight: bold; color: white; }
    .grade-A { background: linear-gradient(135deg, #00b894, #00cec9); }
    .grade-B { background: linear-gradient(135deg, #0984e3, #74b9ff); }
    .grade-C { background: linear-gradient(135deg, #fdcb6e, #ffeaa7); color: #333; }
    .grade-D { background: linear-gradient(135deg, #e17055, #fab1a0); }
    .grade-F { background: linear-gradient(135deg, #d63031, #ff7675); }
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin: 30px 0; }
    .summary-item { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    .summary-item.critical { border-left: 4px solid #d63031; }
    .summary-item.high { border-left: 4px solid #e17055; }
    .summary-item.medium { border-left: 4px solid #fdcb6e; }
    .summary-item.low { border-left: 4px solid #00b894; }
    .summary-item .count { font-size: 2.5em; font-weight: bold; }
    .summary-item .label { color: #666; margin-top: 5px; }
    .section { background: white; border-radius: 10px; padding: 30px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    .section h2 { color: #1a1a2e; border-bottom: 2px solid #eee; padding-bottom: 10px; margin-bottom: 20px; }
    .finding { border-left: 4px solid #ddd; padding: 15px; margin-bottom: 20px; background: #fafafa; border-radius: 0 8px 8px 0; }
    .finding.critical { border-left-color: #d63031; }
    .finding.high { border-left-color: #e17055; }
    .finding.medium { border-left-color: #fdcb6e; }
    .finding.low { border-left-color: #00b894; }
    .finding h3 { margin-bottom: 10px; }
    .badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; color: white; }
    .badge.critical { background: #d63031; }
    .badge.high { background: #e17055; }
    .badge.medium { background: #fdcb6e; color: #333; }
    .badge.low { background: #00b894; }
    .recommendations { background: #f0f8ff; padding: 20px; border-radius: 8px; margin-top: 20px; }
    .recommendations li { margin-bottom: 10px; padding: 10px; background: white; border-radius: 5px; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
    th { background: #1a1a2e; color: white; }
    tr:hover { background: #f5f5f5; }
    .footer { text-align: center; padding: 30px; color: #666; font-size: 0.9em; }
    @media print { body { background: white; } .header { background: #1a1a2e !important; -webkit-print-color-adjust: exact; } }
</style>
"""


def get_report_template(report_data: dict) -> str:
    """Generate complete HTML report."""
    
    exec_summary = report_data.get("executive_summary", {})
    findings = report_data.get("findings", [])
    open_ports = report_data.get("open_ports", [])
    dns_info = report_data.get("dns_info", {})
    whois_info = report_data.get("whois_info", {})
    subdomains = report_data.get("subdomains", [])
    recommendations = report_data.get("recommendations", [])
    
    grade = exec_summary.get("grade", "N/A")
    score = exec_summary.get("overall_score", 0)
    
    findings_html = ""
    for f in findings:
        findings_html += f"""
        <div class="finding {f.get('severity', 'low')}">
            <h3><span class="badge {f.get('severity', 'low')}">{f.get('severity', 'N/A').upper()}</span> {f.get('title', 'Unknown Finding')}</h3>
            <p><strong>CVSS Score:</strong> {f.get('cvss_score', 'N/A')}</p>
            <p><strong>Affected Asset:</strong> {f.get('affected_asset', 'N/A')}</p>
            <p><strong>Description:</strong> {f.get('description', 'No description')}</p>
            <p><strong>Remediation:</strong> {f.get('remediation', 'No remediation available')}</p>
        </div>
        """
    
    ports_html = ""
    for port in open_ports:
        ports_html += f"""
        <tr>
            <td>{port.get('port', 'N/A')}</td>
            <td>{port.get('protocol', 'tcp')}</td>
            <td>{port.get('state', 'unknown')}</td>
            <td>{port.get('service', 'unknown')}</td>
            <td>{port.get('version', 'N/A')}</td>
        </tr>
        """
    
    dns_records_html = ""
    dns_records = dns_info.get("dns_records", {})
    for record_type, values in dns_records.items():
        dns_records_html += f"<tr><td>{record_type}</td><td>{', '.join(values)}</td></tr>"
    
    subdomains_html = ""
    for sub in subdomains[:10]:
        subdomains_html += f"<li>{sub}</li>"
    
    recs_html = ""
    for i, rec in enumerate(recommendations[:5], 1):
        recs_html += f"<li><strong>#{i}:</strong> {rec}</li>"
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Assessment Report - {exec_summary.get('target', 'Unknown')}</title>
        {CSS_STYLES}
    </head>
    <body>
        <div class="container">
            <!-- Header -->
            <div class="header">
                <h1>Security Assessment Report</h1>
                <p class="subtitle">Target: {exec_summary.get('target', 'N/A')}</p>
                <p class="subtitle">Date: {exec_summary.get('assessment_date', 'N/A')}</p>
                <p class="subtitle">Scope: {exec_summary.get('scope', 'VAPT Assessment')}</p>
            </div>
            
            <!-- Score Card -->
            <div class="score-card">
                <h2>Overall Security Score</h2>
                <div class="score-circle grade-{grade}">{score}</div>
                <p style="text-align:center; font-size: 1.5em; margin-top: 10px;">Grade: <strong>{grade}</strong></p>
                <p style="text-align:center; color: #666;">{exec_summary.get('risk_level', 'N/A')} Risk</p>
            </div>
            
            <!-- Summary Grid -->
            <div class="summary-grid">
                <div class="summary-item critical">
                    <div class="count">{exec_summary.get('critical_count', 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-item high">
                    <div class="count">{exec_summary.get('high_count', 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-item medium">
                    <div class="count">{exec_summary.get('medium_count', 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-item low">
                    <div class="count">{exec_summary.get('low_count', 0)}</div>
                    <div class="label">Low</div>
                </div>
            </div>
            
            <!-- Executive Summary -->
            <div class="section">
                <h2>Executive Summary</h2>
                <p>This report presents the findings of an automated vulnerability assessment and penetration test conducted on <strong>{exec_summary.get('target', 'N/A')}</strong>.</p>
                <p>The assessment identified <strong>{exec_summary.get('total_findings', 0)}</strong> security findings across various severity levels.</p>
                <div class="recommendations">
                    <h3>Top Recommendations</h3>
                    <ol>{recs_html}</ol>
                </div>
            </div>
            
            <!-- Findings -->
            <div class="section">
                <h2>Detailed Findings</h2>
                {findings_html if findings_html else '<p>No findings to display.</p>'}
            </div>
            
            <!-- Open Ports -->
            <div class="section">
                <h2>Open Ports & Services</h2>
                <table>
                    <thead>
                        <tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr>
                    </thead>
                    <tbody>{ports_html if ports_html else '<tr><td colspan="5">No open ports detected</td></tr>'}</tbody>
                </table>
            </div>
            
            <!-- DNS Information -->
            <div class="section">
                <h2>DNS Records</h2>
                <table>
                    <thead><tr><th>Record Type</th><th>Values</th></tr></thead>
                    <tbody>{dns_records_html if dns_records_html else '<tr><td colspan="2">No DNS data</td></tr>'}</tbody>
                </table>
            </div>
            
            <!-- Subdomains -->
            <div class="section">
                <h2>Discovered Subdomains</h2>
                <ul>{subdomains_html if subdomains_html else '<li>None discovered</li>'}</ul>
            </div>
            
            <!-- Footer -->
            <div class="footer">
                <p>Generated by VAPT Framework v1.0 | Automated Security Assessment Tool</p>
                <p>Report ID: {report_data.get('report_id', 'N/A')}</p>
            </div>
        </div>
    </body>
    </html>
    """