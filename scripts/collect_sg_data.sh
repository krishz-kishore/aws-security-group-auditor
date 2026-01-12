#!/bin/bash
# AWS Security Group Data Collection Script
# Run this in AWS CloudShell or any environment with AWS CLI configured
# Usage: bash collect_sg_data.sh

echo "==================================="
echo "AWS Security Group Data Collector"
echo "==================================="
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
echo "Regions to scan: $REGIONS"
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

# Loop through each region
for REGION in $REGIONS; do
  echo "----------------------------------------"
  echo "Scanning region: $REGION"
  echo "----------------------------------------"
  
  REGION_DATA="$TEMP_DIR/region_${REGION}.json"
  
  # Get all security groups in the region
  echo "  - Fetching security groups..."
  aws ec2 describe-security-groups --region "$REGION" --output json > "$TEMP_DIR/sgs_${REGION}.json" 2>/dev/null
  
  if [ $? -ne 0 ]; then
    echo "  - ERROR: Failed to access region $REGION. Skipping..."
    continue
  fi
  
  SG_COUNT=$(jq '.SecurityGroups | length' "$TEMP_DIR/sgs_${REGION}.json")
  echo "  - Found $SG_COUNT security groups"
  
  # Get network interfaces (to find attachments)
  echo "  - Fetching network interfaces..."
  aws ec2 describe-network-interfaces --region "$REGION" --output json > "$TEMP_DIR/enis_${REGION}.json" 2>/dev/null
  
  # Get instances (for additional context)
  echo "  - Fetching EC2 instances..."
  aws ec2 describe-instances --region "$REGION" --output json > "$TEMP_DIR/instances_${REGION}.json" 2>/dev/null
  
  # Get VPC information
  echo "  - Fetching VPC information..."
  aws ec2 describe-vpcs --region "$REGION" --output json > "$TEMP_DIR/vpcs_${REGION}.json" 2>/dev/null
  
  # Process and combine data for this region
  jq -n \
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
    }' > "$REGION_DATA"
  
  REGION_COUNT=$((REGION_COUNT + 1))
  echo "   Region $REGION completed"
  echo ""
done

# Combine all region data into final JSON
echo "Combining data from all regions..."

# Build regions array using file-based approach (avoids "Argument list too long" error)
echo "[" > "$TEMP_DIR/regions_array.json"
FIRST=true
for REGION in $REGIONS; do
  REGION_FILE="$TEMP_DIR/region_${REGION}.json"
  if [ -f "$REGION_FILE" ]; then
    if [ "$FIRST" = true ]; then
      FIRST=false
    else
      echo "," >> "$TEMP_DIR/regions_array.json"
    fi
    cat "$REGION_FILE" >> "$TEMP_DIR/regions_array.json"
  fi
done
echo "]" >> "$TEMP_DIR/regions_array.json"

# Create final JSON using file input instead of command-line args
jq --slurpfile regions "$TEMP_DIR/regions_array.json" '.regions = $regions[0]' "$TEMP_DIR/base.json" > "$OUTPUT_FILE"

# Verify output file was created and is not empty
if [ ! -s "$OUTPUT_FILE" ]; then
  echo "ERROR: Output file is empty or was not created!"
  echo "Temp directory preserved for debugging: $TEMP_DIR"
  exit 1
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo "==================================="
echo "Data collection completed!"
echo "==================================="
echo ""
echo "Output file: $OUTPUT_FILE"
echo "File size: $(du -h "$OUTPUT_FILE" | cut -f1)"
echo "Regions scanned: $REGION_COUNT"
echo "Total security groups: $(jq '[.regions[].security_groups | length] | add' "$OUTPUT_FILE")"
echo ""
echo "Next steps:"
echo "1. Download this file: $OUTPUT_FILE"
echo "2. Run the local report generator with this JSON file"
echo ""
