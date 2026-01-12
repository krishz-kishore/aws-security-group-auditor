# QUICK START GUIDE
# AWS Security Group Auditor

## Prerequisites
✅ Python 3.9+ installed
✅ AWS Console access
✅ IAM permissions for EC2 read operations

## Installation (Already Done!)
```powershell
.\setup.ps1
```

## Usage (2 Simple Steps)

### STEP 1: Collect AWS Data
```bash
# In AWS CloudShell:
# 1. Upload scripts/collect_sg_data.sh
# 2. Run:
bash collect_sg_data.sh

# 3. Download the generated JSON file:
#    sg_audit_data_YYYYMMDD_HHMMSS.json
```

### STEP 2: Generate Report
```powershell
# On your local machine:
python run_audit.py sg_audit_data_20260112_143022.json
```

## Output Location
- HTML: `output/security_report_*.html`
- PDF:  `output/security_report_*.pdf`
- Charts: `output/*.png`

## What Gets Detected

###  CRITICAL
- Databases exposed to internet (MySQL, PostgreSQL, MongoDB, etc.)
- All protocols/ports open to 0.0.0.0/0
- Telnet exposed publicly

###  HIGH  
- SSH (22) or RDP (3389) from internet
- Management ports exposed
- Redis, Elasticsearch without restrictions

###  MEDIUM
- HTTP/HTTPS without WAF
- Other service ports with public access

### ℹ INFO
- Unused security groups

## Troubleshooting

### WeasyPrint PDF Issues on Windows
If PDF generation fails:
1. Install GTK+ from: https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer
2. Or use HTML report and browser "Print to PDF"

### AWS CloudShell Issues
- Ensure you have correct IAM permissions
- Check region is enabled
- Try running script in different region

## Support Files
- `README.md` - Detailed documentation
- `PLAN.md` - Technical implementation details

---
Created: January 12, 2026
