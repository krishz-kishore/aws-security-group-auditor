#!/usr/bin/env python3
"""
AWS Security Group Audit - Main Runner
Generates security audit report from AWS CLI collected data
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from report_generator import generate_report


def main():
    """Main entry point for the audit report generator."""
    print("""

   AWS Security Group Audit Report Generator           
   Professional Security Analysis & Reporting           
════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python run_audit.py <json_data_file>")
        print()
        print("Example:")
        print("  python run_audit.py sg_audit_data_20260112_143022.json")
        print()
        print("To collect data, run the AWS CloudShell script:")
        print("  bash scripts/collect_sg_data.sh")
        print()
        sys.exit(1)
    
    json_file = sys.argv[1]
    
    if not os.path.exists(json_file):
        print(f" Error: File not found: {json_file}")
        sys.exit(1)
    
    try:
        generate_report(json_file)
    except Exception as e:
        print(f" Error generating report: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
