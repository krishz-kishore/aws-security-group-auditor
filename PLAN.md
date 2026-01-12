# AWS Security Group Auditor - Implementation Plan

**Created:** January 12, 2026
**Status:** Deployed

## Overview

Two-part solution for AWS Security Group auditing that eliminates credential management:
1. **AWS CloudShell script** - Collects data directly in AWS environment
2. **Local Python analyzer** - Generates professional PDF reports

## Architecture

### Part 1: Data Collection (AWS CloudShell)
- **File:** `scripts/collect_sg_data.sh`
- **Runtime:** AWS CloudShell (bash + AWS CLI)
- **Output:** Timestamped JSON file with complete SG data
- **Regions:** Scans all enabled regions automatically
- **IAM Permissions Required:** Read-only EC2, STS, IAM

### Part 2: Report Generation (Local)
- **File:** `src/report_generator.py`
- **Runtime:** Local Python 3.9+
- **Input:** JSON file from Part 1
- **Output:** HTML + PDF reports

## Risk Analysis Framework

### Industry-Standard Risk Criteria

**Critical ( Immediate Action)**
- Database ports (3306, 5432, 1433, 27017, 6379, 9200) exposed to 0.0.0.0/0
- All protocols/ports open to internet
- Telnet (23) exposed publicly

**High ( Urgent)**
- SSH (22), RDP (3389) accessible from 0.0.0.0/0
- Management ports (5900, 5985, 5986) exposed
- Common risky ports without IP restrictions

**Medium ( Important)**
- HTTP/HTTPS exposed without WAF/CloudFront
- Other service ports with public access

**Low (ℹ)**
- Overly permissive egress rules

**Info**
- Unused security groups (no attachments)

### Detection Logic

1. **Risky Port Detection**
   - Check ingress rules against RISKY_PORTS dictionary
   - Flag if source CIDR is 0.0.0.0/0 or ::/0
   - Severity based on port criticality

2. **Unused Security Group Detection**
   - Cross-reference with network interfaces
   - Mark as unused if no ENI attachments
   - Exclude default security groups

3. **Rule Overlap Detection** (Future Enhancement)
   - Compare rules across security groups
   - Identify redundant or conflicting rules
   - Suggest consolidation opportunities

## Report Structure

### Executive Summary
- Total SGs analyzed
- Risk distribution (Critical/High/Medium/Low)
- Unused resources count
- Visual charts (pie + bar)

### Critical Findings Section
- Detailed risk information
- Security group details
- Affected resources
- Specific remediation steps

### High/Medium/Low Findings
- Similar structure to critical
- Prioritized by severity

### Unused Resources
- Table format for easy review
- Region and VPC context

### Visualizations
- Severity distribution (donut chart)
- Statistics overview (bar chart)
- Corporate color scheme

## Technology Stack

### AWS CloudShell Script
- Bash shell scripting
- AWS CLI v2
- jq (JSON processor)

### Local Report Generator
```
Python 3.9+
 boto3          # AWS SDK (for future enhancements)
 jinja2         # HTML templating
 weasyprint     # HTML to PDF conversion
 pandas         # Data manipulation
 plotly         # Interactive charts
 kaleido        # Static image export
```

## Project Structure

```
AWS Security/
 src/
    __init__.py
    report_generator.py          # Core analyzer + report generator
 templates/
    report_template.html         # Jinja2 template (corporate style)
 scripts/
    collect_sg_data.sh          # AWS CloudShell data collector
 output/                          # Generated reports (gitignored)
 .github/
    agents/                     # Agent configurations
    instructions/               # Coding standards
 requirements.txt                # Python dependencies
 run_audit.py                   # Main entry point
 setup.ps1                      # Windows setup script
 .gitignore
 README.md
 PLAN.md (this file)
```

## Usage Workflow

### Initial Setup (One-time)
```powershell
# On local machine
.\setup.ps1
```

### Data Collection (In AWS)
```bash
# In AWS CloudShell
bash collect_sg_data.sh
# Download: sg_audit_data_YYYYMMDD_HHMMSS.json
```

### Report Generation (Local)
```powershell
python run_audit.py sg_audit_data_20260112_143022.json
```

### Output
- `output/security_report_YYYYMMDD_HHMMSS.html` - Interactive HTML
- `output/security_report_YYYYMMDD_HHMMSS.pdf` - Executive PDF
- `output/*.png` - Chart images

## Security Considerations

### Data Collection
-  No credentials stored locally
-  Read-only AWS permissions
-  Runs in AWS managed environment
-  Automatic cleanup of temp files

### IAM Permissions (Minimum Required)
```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": [
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeInstances",
            "ec2:DescribeRegions",
            "ec2:DescribeVpcs",
            "sts:GetCallerIdentity",
            "iam:ListAccountAliases"
        ],
        "Resource": "*"
    }]
}
```

### Data Processing
- All analysis done locally
- No data sent to external services
- JSON files should be treated as confidential

## Future Enhancements

### Phase 2 Features (Not Yet Implemented)
1. **Rule Overlap Detection**
   - Identify redundant rules across SGs
   - Suggest consolidation opportunities
   - Complexity scoring

2. **Compliance Frameworks**
   - CIS AWS Foundations Benchmark
   - PCI-DSS requirements
   - HIPAA compliance checks

3. **Trend Analysis**
   - Compare multiple scan results
   - Track remediation progress
   - Risk score trending

4. **Multi-Account Support**
   - AWS Organizations integration
   - Consolidated reporting
   - Cross-account comparison

5. **Automated Remediation**
   - Generate CloudFormation templates
   - Suggest AWS Config rules
   - Create remediation scripts

6. **Integration Features**
   - Jira ticket creation
   - Slack notifications
   - Email distribution

## Code Quality Standards

### Python Code (PEP 8)
- Type hints for all functions
- Comprehensive docstrings (PEP 257)
- 4-space indentation
- Maximum 79 characters per line
- Clear comments for complex logic

### Testing Strategy (Future)
- Unit tests for risk detection logic
- Integration tests with sample data
- PDF generation validation
- Chart rendering tests

## Technical Debt & Known Limitations

### Current Limitations
1. **WeasyPrint Windows Compatibility**
   - Requires GTK+ runtime on Windows
   - Fallback: Use browser "Print to PDF"

2. **Large Datasets**
   - Report size grows with findings
   - Consider pagination for 1000+ findings

3. **Rule Overlap Detection**
   - Not yet implemented
   - Placeholder in stats structure

### Planned Improvements
1. Add progress indicators for long-running scans
2. Implement incremental report generation
3. Add export to CSV/Excel formats
4. Create interactive dashboard (web UI)

## Maintenance Notes

### Updating Risk Criteria
- Edit `RISKY_PORTS` dictionary in `SecurityGroupAnalyzer`
- Adjust severity logic in `_check_risky_cidr()`
- Update documentation in README.md

### Modifying Report Style
- Edit `templates/report_template.html`
- Adjust CSS in `<style>` section
- Corporate colors: #0066cc (primary), #dc3545 (critical)

### Adding New Charts
- Extend `generate_charts()` function
- Use plotly for interactive/static charts
- Save as PNG in output directory

## References

- AWS Security Best Practices: https://docs.aws.amazon.com/security/
- CIS AWS Foundations Benchmark: https://www.cisecurity.org/
- OWASP Cloud Security: https://owasp.org/www-project-cloud-security/

---

**Implementation Status:**  Complete and deployed
**Last Updated:** January 12, 2026
**Next Review:** As needed for enhancements
