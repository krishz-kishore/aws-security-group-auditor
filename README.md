# AWS Security Group Auditor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![AWS](https://img.shields.io/badge/AWS-CloudShell-orange.svg)](https://aws.amazon.com/cloudshell/)
[![Code Quality](https://img.shields.io/badge/code%20quality-A-brightgreen.svg)](https://github.com/krishz-kishore/aws-security-group-auditor)
[![Maintainability](https://img.shields.io/badge/maintainability-A-brightgreen.svg)](https://github.com/krishz-kishore/aws-security-group-auditor)
[![CodeFactor](https://www.codefactor.io/repository/github/krishz-kishore/aws-security-group-auditor/badge)](https://www.codefactor.io/repository/github/krishz-kishore/aws-security-group-auditor)

Professional security analysis and reporting tool for AWS Security Groups. Identifies risky configurations, unused resources, and generates executive-ready reports with interactive dark theme support.

Perfect for security audits, compliance checks, and identifying security group misconfigurations across your entire AWS infrastructure.

## ✨ Features

- 🌍 **Multi-Region Scanning** - Automatically analyzes all enabled AWS regions
- 🔒 **Industry-Standard Risk Detection** - Based on CIS AWS Foundations, NIST, and OWASP guidelines
- 🎯 **Smart Risk Classification** - CRITICAL, HIGH, MEDIUM, LOW, and INFO severity levels
- ✅ **Unused Resource Detection** - Identifies security groups with no attachments
- 📊 **Professional Reports** - Corporate-styled HTML reports with charts and visualizations
- 🔐 **No Credential Storage** - Data collection runs securely in AWS CloudShell
- 🌙 **Dark Theme Support** - Toggle between light and dark modes with persistent preference
- 📈 **Visual Analytics** - Interactive charts showing severity distribution and statistics
- 📋 **Detailed Methodology** - Clear explanation of risk evaluation criteria
- 🔍 **Comprehensive Inventory** - Complete table of all security groups with ports and IPs

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- AWS Account with appropriate IAM permissions (read-only)
- AWS CLI access (for data collection)

### Step 1: Clone the Repository

```bash
git clone https://github.com/krishz-kishore/aws-security-group-auditor.git
cd aws-security-group-auditor
```

### Step 2: Set Up Python Virtual Environment

**On Windows (PowerShell):**
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

**On Linux/macOS:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Collect AWS Data

1. Log into AWS Console
2. Open **CloudShell** (icon in top navigation bar)
3. Upload the script: `scripts/collect_sg_data.sh`
4. Run the script:
   ```bash
   bash collect_sg_data.sh
   ```
5. Wait for the scan to complete (analyzes all regions)
6. Download the generated JSON file (e.g., `sg_audit_data_YYYYMMDD_HHMMSS.json`)

### Step 4: Generate Report Locally

```bash
# Ensure virtual environment is activated
python run_audit.py path/to/sg_audit_data_YYYYMMDD_HHMMSS.json
```

### Step 5: View Your Report

Open `output/security_report_YYYYMMDD_HHMMSS.html` in your browser. Use the 🌙/☀️ button to toggle between light and dark themes!

## 🎯 Risk Categories

### 🔴 Critical
- Database ports (MySQL 3306, PostgreSQL 5432, SQL Server 1433, MongoDB 27017, Redis 6379, Elasticsearch 9200) exposed to internet (0.0.0.0/0)
- All protocols/ports open to internet
- Telnet (port 23) accessible from anywhere

**Impact:** Immediate risk of data breach, ransomware, unauthorized access to sensitive data  
**Action:** Remediate within 24 hours

### 🟠 High
- SSH (22) or RDP (3389) accessible from internet
- Management ports (VNC 5900, WinRM 5985/5986) exposed publicly
- FTP (20/21), SMTP (25), SMB (445) without IP restrictions

**Impact:** Unauthorized administrative access, brute force attacks, credential theft  
**Action:** Remediate within 7 days

### 🟡 Medium
- HTTP/HTTPS services exposed without CloudFront/ALB protection
- Application ports with overly broad CIDR ranges
- Non-standard ports accessible from internet

**Impact:** Increased attack surface, potential DoS vectors  
**Action:** Review and remediate within 30 days

### ℹ️ Info
- Unused security groups (no attachments)
- Optimization opportunities
- Best practice recommendations

## 📊 Report Features

The generated HTML report includes:

- **Executive Summary** - High-level metrics and severity breakdown
- **Risk Evaluation Methodology** - Detailed explanation of each severity level
- **Visual Charts** - Severity distribution pie chart and statistics
- **Active Security Groups Inventory** - Complete table with all ingress rules, ports, protocols, and source IPs
- **Detailed Findings** - Individual findings with:
  - Security group name and ID
  - Region and VPC information
  - Specific rule details
  - Attached resources count
  - Actionable recommendations
- **Unused Security Groups** - List of SGs with no attachments
- **Dark Theme Toggle** - Switch between light/dark modes (preference saved)

## 📦 Requirements

- Python 3.9 or higher
- AWS CLI (for data collection in CloudShell)
- Python packages (auto-installed via requirements.txt):
  - boto3 - AWS SDK
  - jinja2 - Template engine
  - pandas - Data analysis
  - plotly - Chart generation
  - kaleido - Static image export

## 🔐 Security & Privacy

- ✅ **No AWS credentials stored locally** - Data collection runs in your AWS CloudShell environment
- ✅ **Read-only permissions** - Script only queries information, never modifies resources
- ✅ **Local processing** - All analysis happens on your machine
- ✅ **No external API calls** - Complete privacy and data control
- ✅ **Open source** - Review all code before running

## 🔑 IAM Permissions Required

The AWS CloudShell script requires **read-only** permissions:

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

> **Note:** These permissions are read-only and do not allow any modifications to your AWS resources.
```

## 📁 Project Structure

```
aws-security-group-auditor/
├── src/
│   ├── __init__.py
│   └── report_generator.py      # Core analysis engine
├── templates/
│   └── report_template.html     # HTML report template with dark theme
├── scripts/
│   └── collect_sg_data.sh       # AWS CloudShell data collector
├── output/                       # Generated reports (created automatically)
├── venv/                         # Virtual environment (create this)
├── requirements.txt              # Python dependencies
├── run_audit.py                  # Main CLI entry point
└── README.md
```

## ❓ Troubleshooting

### Virtual Environment Not Activating

**Windows:**
```powershell
# If you get execution policy error
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then activate
.\venv\Scripts\Activate.ps1
```

**Linux/macOS:**
```bash
# Make sure you're using the correct Python version
python3 --version

# Activate venv
source venv/bin/activate
```

### Missing AWS Permissions

If the CloudShell script fails, ensure your IAM user/role has the required read-only permissions listed above.

### Empty or Invalid JSON Output

If you get an empty JSON file:
1. Check CloudShell output for errors
2. Ensure you have security groups in at least one region
3. Verify IAM permissions are correctly set

### Converting Report to PDF

The tool generates HTML reports. To convert to PDF:
1. Open the HTML report in your browser
2. Press `Ctrl+P` (Windows/Linux) or `Cmd+P` (macOS)
3. Select "Save as PDF" as the destination
4. Adjust settings and save

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⭐ Star This Repository

If you find this tool useful, please consider giving it a star! It helps others discover the project.

## 📧 Support

For issues, questions, or suggestions, please [open an issue](https://github.com/krishz-kishore/aws-security-group-auditor/issues) on GitHub.

---

**Made with ❤️ for the AWS Security Community**