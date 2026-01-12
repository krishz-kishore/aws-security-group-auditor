#!/bin/bash
# AWS Security Group Data Collection Script - IMPROVED VERSION
# Run this in AWS CloudShell or any environment with AWS CLI configured
# Usage: bash collect_sg_data_v2.sh

set -e  # Exit on error
set -o pipefail  # Catch errors in pipes

echo "==========================================="
echo "AWS Security Group Data Collector v2"
echo "==========================================="
echo ""

# Check prerequisites
echo "Checking prerequisites..."
if ! command -v aws &> /dev/null; then
    echo "ERROR: AWS CLI not found!"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "ERROR: jq not found! Installing..."
    # Try to install jq if not present
    if command -v yum &> /dev/null; then
        sudo yum install -y jq
    elif command -v apt-get &> /dev/null; then
        sudo apt-get install -y jq
    else
        echo "ERROR: Cannot install jq automatically. Please install manually."
        exit 1
    fi
fi

echo " AWS CLI: $(aws --version)"
echo " jq: $(jq --version)"
echo ""

# Test AWS credentials
echo "Testing AWS credentials..."
if ! aws sts get-caller-identity &> /dev/null; then
    echo "ERROR: AWS credentials not configured or insufficient permissions!"
    echo "Please ensure you have the required IAM permissions."
    exit 1
fi
echo " AWS credentials valid"
echo ""

OUTPUT_FILE="sg_audit_data_$(date +%Y%m%d_%H%M%S).json"
TEMP_DIR="/tmp/sg_audit_$$"
mkdir -p "$TEMP_DIR"

echo "Collecting AWS account information..."
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ACCOUNT_ALIAS=$(aws iam list-account-aliases --query 'AccountAliases[0]' --output text 2>/dev/null || echo "N/A")

echo "Account ID: $ACCOUNT_ID"
echo "Account Alias: $ACCOUNT_ALIAS"
echo ""

# Get all enabled regions
echo "Discovering enabled regions..."
REGIONS=$(aws ec2 describe-regions --query 'Regions[?OptInStatus!=`not-opted-in`].RegionName' --output text)

if [ -z "$REGIONS" ]; then
    echo "ERROR: No regions found or unable to query regions!"
    exit 1
fi

echo "Regions to scan: $REGIONS"
REGION_ARRAY=($REGIONS)
echo "Total regions: ${#REGION_ARRAY[@]}"
echo ""

# Initialize JSON structure
cat > "$TEMP_DIR/base.json" <<EOF
{
  "scan_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "account_id": "$ACCOUNT_ID",
  "account_alias": "$ACCOUNT_ALIAS",
  "regions": []
}
EOF

REGION_COUNT=0
SUCCESS_COUNT=0
FAIL_COUNT=0

# Loop through each region
for REGION in $REGIONS; do
  echo ""
  echo "Scanning region: $REGION"
  echo ""
  
  REGION_DATA="$TEMP_DIR/region_${REGION}.json"
  
  # Get all security groups in the region
  echo "  [1/4] Fetching security groups..."
  if aws ec2 describe-security-groups --region "$REGION" --output json > "$TEMP_DIR/sgs_${REGION}.json" 2>/dev/null; then
    SG_COUNT=$(jq '.SecurityGroups | length' "$TEMP_DIR/sgs_${REGION}.json" 2>/dev/null || echo "0")
    echo "         Found $SG_COUNT security groups"
  else
    echo "         Failed to access region $REGION. Skipping..."
    FAIL_COUNT=$((FAIL_COUNT + 1))
    continue
  fi
  
  # Get network interfaces (to find attachments)
  echo "  [2/4] Fetching network interfaces..."
  if aws ec2 describe-network-interfaces --region "$REGION" --output json > "$TEMP_DIR/enis_${REGION}.json" 2>/dev/null; then
    ENI_COUNT=$(jq '.NetworkInterfaces | length' "$TEMP_DIR/enis_${REGION}.json" 2>/dev/null || echo "0")
    echo "         Found $ENI_COUNT network interfaces"
  else
    echo "         Failed to fetch network interfaces"
    echo '{"NetworkInterfaces":[]}' > "$TEMP_DIR/enis_${REGION}.json"
  fi
  
  # Get instances (for additional context)
  echo "  [3/4] Fetching EC2 instances..."
  if aws ec2 describe-instances --region "$REGION" --output json > "$TEMP_DIR/instances_${REGION}.json" 2>/dev/null; then
    INST_COUNT=$(jq '.Reservations | length' "$TEMP_DIR/instances_${REGION}.json" 2>/dev/null || echo "0")
    echo "         Found $INST_COUNT reservations"
  else
    echo "         Failed to fetch instances"
    echo '{"Reservations":[]}' > "$TEMP_DIR/instances_${REGION}.json"
  fi
  
  # Get VPC information
  echo "  [4/4] Fetching VPC information..."
  if aws ec2 describe-vpcs --region "$REGION" --output json > "$TEMP_DIR/vpcs_${REGION}.json" 2>/dev/null; then
    VPC_COUNT=$(jq '.Vpcs | length' "$TEMP_DIR/vpcs_${REGION}.json" 2>/dev/null || echo "0")
    echo "         Found $VPC_COUNT VPCs"
  else
    echo "         Failed to fetch VPCs"
    echo '{"Vpcs":[]}' > "$TEMP_DIR/vpcs_${REGION}.json"
  fi
  
  # Process and combine data for this region
  echo "  [*] Processing region data..."
  if jq -n \
    --arg region "$REGION" \
    --slurpfile sgs "$TEMP_DIR/sgs_${REGION}.json" \
    --slurpfile enis "$TEMP_DIR/enis_${REGION}.json" \
    --slurpfile instances "$TEMP_DIR/instances_${REGION}.json" \
    --slurpfile vpcs "$TEMP_DIR/vpcs_${REGION}.json" \
    '{
      region_name: $region,
      security_groups: $sgs[0].SecurityGroups,
      network_interfaces: $enis[0].NetworkInterfaces,
      instances: $instances[0].Reservations,
      vpcs: $vpcs[0].Vpcs
    }' > "$REGION_DATA" 2>/dev/null; then
    echo "         Region $REGION completed successfully"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
  else
    echo "         Failed to process region data"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
  
  REGION_COUNT=$((REGION_COUNT + 1))
  echo ""
done

# Combine all region data into final JSON
echo ""
echo "Combining data from all regions..."
echo ""

# Build regions array
REGIONS_JSON="["
FIRST=true
for REGION in $REGIONS; do
  REGION_FILE="$TEMP_DIR/region_${REGION}.json"
  if [ -f "$REGION_FILE" ]; then
    if [ "$FIRST" = true ]; then
      FIRST=false
    else
      REGIONS_JSON+=","
    fi
    REGIONS_JSON+=$(cat "$REGION_FILE")
  fi
done
REGIONS_JSON+="]"

# Create final JSON
if jq --argjson regions "$REGIONS_JSON" '.regions = $regions' "$TEMP_DIR/base.json" > "$OUTPUT_FILE" 2>/dev/null; then
  echo " Final JSON created successfully"
else
  echo " ERROR: Failed to create final JSON!"
  echo "Check temp files in: $TEMP_DIR"
  exit 1
fi

# Verify output file is not empty
if [ ! -s "$OUTPUT_FILE" ]; then
  echo " ERROR: Output file is empty!"
  echo "Check temp files in: $TEMP_DIR"
  exit 1
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo ""
echo "==========================================="
echo " Data collection completed successfully!"
echo "==========================================="
echo ""
echo "Output file: $OUTPUT_FILE"
echo "File size: $(du -h "$OUTPUT_FILE" | cut -f1)"
echo "Regions processed: $REGION_COUNT"
echo "  - Successful: $SUCCESS_COUNT"
echo "  - Failed: $FAIL_COUNT"
echo "Total security groups: $(jq '[.regions[].security_groups | length] | add' "$OUTPUT_FILE" 2>/dev/null || echo "0")"
echo ""
echo "Next steps:"
echo "1. Download this file: $OUTPUT_FILE"
echo "2. Run: python run_audit.py $OUTPUT_FILE"
echo ""
