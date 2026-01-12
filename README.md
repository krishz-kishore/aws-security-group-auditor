# AWS Security Group Auditor

Professional security analysis and reporting tool for AWS Security Groups. Identifies risky configurations, unused resources, and generates executive-ready reports with dark theme support.

## Features

- 🌍 **Multi-Region Scanning** - Analyzes all enabled AWS regions
- 🔒 **Industry-Standard Risk Detection** - Identifies risky ports and configurations
- ✅ **Unused Resource Detection** - Finds security groups with no attachments
- 📊 **Professional Reports** - Corporate-styled HTML reports with interactive dark theme
- 🔐 **No Credential Storage** - Data collection runs in AWS CloudShell
- 🌙 **Dark Theme Support** - Toggle between light and dark modes with persistent preference

## Quick Start

### Step 1: Collect AWS Data

1. Log into AWS Console
2. Open CloudShell (icon in top navigation bar)
3. Upload the script: `scripts/collect_sg_data.sh`
4. Run the script:
   ```bash
   bash collect_sg_data.sh
   ```
5. Download the generated JSON file (e.g., `sg_audit_data_20260112_143022.json`)

### Step 2: Generate Report Locally

1. Install Python dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

2. Run the report generator:
   ```powershell
   python run_audit.py sg_audit_data_20260112_143022.json
   ```

3. Find your reports in the `output/` directory:
   - HTML version (viewable in browser)
   - PDF version (ready to share)

## Risk Categories

### Critical 
- Database ports (3306, 5432, 1433, etc.) exposed to internet
- All protocols/ports open to 0.0.0.0/0
- Redis, MongoDB, Elasticsearch exposed publicly

### High 
- SSH (22) or RDP (3389) accessible from internet
- Management ports exposed publicly
- Common service ports without IP restrictions

### Medium 
- HTTP services exposed to internet without CloudFront/ALB
- Other risky ports with public access

### Info ℹ
- Unused security groups (no attachments)
- Optimization opportunities

## Requirements

- Python 3.9+
- AWS CLI configured (for data collection)
- Libraries: boto3, jinja2, weasyprint, pandas, plotly

## Output

Reports include:
- Executive summary with risk metrics
- Visual charts and graphs
- Detailed findings by severity
- Specific recommendations
- Resource attachment information
- Region-by-region analysis

## Security

- No AWS credentials stored locally
- Read-only AWS permissions required
- Data collection runs in your AWS environment
- All processing done locally

## IAM Permissions Required

The AWS CloudShell script requires read-only permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
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
        }
    ]
}
```

## Project Structure

```
AWS Security/
 src/
    __init__.py
    report_generator.py     # Main analysis and report generation
 templates/
    report_template.html    # Professional HTML template
 scripts/
    collect_sg_data.sh      # AWS CloudShell data collection
 output/                     # Generated reports
 requirements.txt
 run_audit.py               # Main entry point
 README.md
```

## Troubleshooting

### WeasyPrint Installation Issues on Windows
If you encounter issues installing weasyprint:
```powershell
# Install GTK+ for Windows first
# Download from: https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases
# Then install Python packages
pip install weasyprint
```

### Alternative: HTML-only Reports
If PDF generation fails, you can still use the HTML reports:
1. Open the HTML file in a browser
2. Use browser's "Print to PDF" feature

## License

Internal Use Only - Confidential