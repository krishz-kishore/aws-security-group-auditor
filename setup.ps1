# AWS Security Group Auditor - Setup Script
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AWS Security Group Auditor - Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Python version
Write-Host "Checking Python version..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Python not found. Please install Python 3.9 or higher." -ForegroundColor Red
    exit 1
}
Write-Host "   $pythonVersion" -ForegroundColor Green
Write-Host ""

# Create directories
Write-Host "Creating directory structure..." -ForegroundColor Yellow
$dirs = @("src", "templates", "output", "scripts")
foreach ($dir in $dirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "   Created $dir/" -ForegroundColor Green
    } else {
        Write-Host "   $dir/ already exists" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
Write-Host "This may take a few minutes..." -ForegroundColor Gray
pip install -q -r requirements.txt

if ($LASTEXITCODE -eq 0) {
    Write-Host "   Dependencies installed successfully" -ForegroundColor Green
} else {
    Write-Host "   Some dependencies may have failed. Check errors above." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "1. Log into AWS Console and open CloudShell" -ForegroundColor White
Write-Host "2. Upload scripts/collect_sg_data.sh to CloudShell" -ForegroundColor White
Write-Host "3. Run: bash collect_sg_data.sh" -ForegroundColor White
Write-Host "4. Download the generated JSON file" -ForegroundColor White
Write-Host "5. Run: python run_audit.py <json_file>" -ForegroundColor White
Write-Host ""
Write-Host "Example:" -ForegroundColor Cyan
Write-Host "  python run_audit.py sg_audit_data_20260112_143022.json" -ForegroundColor Gray
Write-Host ""
