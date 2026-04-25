#!/usr/bin/env bash
# Analyze all 7 systems from APT attack scenario
# Run this script to process the entire enterprise compromise

set -euo pipefail

# Evidence base directory
EVIDENCE_BASE="/media/jtomek/TESLADRIVE/sift_evidence/compromised_apt_attack/SRL-2015-Compromised_Enterprise_Network"
OUTPUT_BASE="/cases/apt_attack_2015"
MOUNT_BASE="/mnt/apt_analysis"

# Ensure output directory exists
mkdir -p "$OUTPUT_BASE"
mkdir -p "$MOUNT_BASE"

# System definitions
declare -A SYSTEMS=(
  ["dmz_ftp"]="dmz-ftp-cdrive.E01"
  ["domain_controller"]="base-dc-cdrive.E01"
  ["file_server"]="base-file-cdrive.E01"
  ["rd_01"]="base-rd-01-cdrive.E01"
  ["rd_02"]="base-rd-02-cdrive.E01"
  ["workstation_01"]="base-wkstn-01-c-drive.E01"
  ["workstation_05"]="base-wkstn-05-cdrive.E01"
)

# Analysis order (prioritize likely initial compromise and high-value targets)
ANALYSIS_ORDER=(
  "dmz_ftp"           # Initial compromise likely here
  "workstation_01"    # User workstation, lateral movement target
  "domain_controller" # Highest-value target, privilege escalation
  "file_server"       # Data exfiltration target
  "rd_01"             # Persistence mechanism
  "rd_02"             # Persistence mechanism
  "workstation_05"    # Additional workstation
)

# Function to mount E01 image
mount_image() {
  local system_name=$1
  local image_file=$2

  echo "========================================================================"
  echo "  Mounting: $system_name"
  echo "========================================================================"

  local ewf_mount="$MOUNT_BASE/${system_name}_ewf"
  local ntfs_mount="$MOUNT_BASE/${system_name}_ntfs"

  # Create mount points
  sudo mkdir -p "$ewf_mount" "$ntfs_mount"

  # Mount E01 with ewfmount
  echo "[1/3] Mounting E01 image with ewfmount..."
  sudo ewfmount "$EVIDENCE_BASE/$image_file" "$ewf_mount"

  # Get partition offset
  echo "[2/3] Analyzing partition structure..."
  local partition_info
  partition_info=$(sudo mmls "$ewf_mount/ewf1" 2>/dev/null | grep -E "NTFS|Basic data|Microsoft" | head -1)

  if [[ -z "$partition_info" ]]; then
    echo "ERROR: No NTFS partition found in $image_file"
    sudo umount "$ewf_mount" 2>/dev/null || true
    return 1
  fi

  local offset_sectors
  offset_sectors=$(echo "$partition_info" | awk '{print $3}')
  local offset_bytes=$((offset_sectors * 512))

  echo "    Partition offset: $offset_sectors sectors ($offset_bytes bytes)"

  # Mount NTFS partition read-only
  echo "[3/3] Mounting NTFS partition (read-only)..."
  sudo mount -o ro,loop,offset="$offset_bytes" "$ewf_mount/ewf1" "$ntfs_mount"

  echo "✓ Mounted: $ntfs_mount"
  echo ""

  echo "$ntfs_mount"  # Return mount point
}

# Function to unmount image
unmount_image() {
  local system_name=$1

  local ewf_mount="$MOUNT_BASE/${system_name}_ewf"
  local ntfs_mount="$MOUNT_BASE/${system_name}_ntfs"

  echo "Unmounting $system_name..."
  sudo umount "$ntfs_mount" 2>/dev/null || true
  sudo umount "$ewf_mount" 2>/dev/null || true
  sudo rm -rf "$ewf_mount" "$ntfs_mount" 2>/dev/null || true
}

# Function to analyze single system
analyze_system() {
  local system_name=$1
  local image_file=$2

  echo "========================================================================"
  echo "  Analyzing: $system_name"
  echo "========================================================================"
  echo "Image: $image_file"
  echo "Output: $OUTPUT_BASE/$system_name"
  echo ""

  # Mount image
  local mount_point
  mount_point=$(mount_image "$system_name" "$image_file")

  if [[ -z "$mount_point" ]]; then
    echo "ERROR: Failed to mount $system_name"
    return 1
  fi

  # Verify MFT exists
  if [[ ! -f "$mount_point/\$MFT" ]]; then
    echo "ERROR: \$MFT not found in $mount_point"
    unmount_image "$system_name"
    return 1
  fi

  local mft_size
  mft_size=$(stat -f "%z" "$mount_point/\$MFT" 2>/dev/null || stat -c "%s" "$mount_point/\$MFT")
  echo "\$MFT size: $((mft_size / 1024 / 1024)) MB"
  echo ""

  # Run analysis with sift_find_evil (using --windows-mount for auto-detection)
  echo "Running detection engine with full artifact auto-detection..."
  cd ~/Code/sift_find_evil
  source venv/bin/activate

  python -m sift_find_evil.cli_mcp analyze-live \
    --case-id "apt_${system_name}" \
    --windows-mount "$mount_point" \
    --output-dir "$OUTPUT_BASE/$system_name" \
    --timeout 900

  # Unmount
  unmount_image "$system_name"

  echo ""
  echo "✓ Analysis complete: $system_name"
  echo "  Findings: $OUTPUT_BASE/$system_name/findings.json"
  echo "  Audit log: $OUTPUT_BASE/$system_name/audit.jsonl"
  echo ""
}

# Main execution
main() {
  echo "========================================================================"
  echo "  APT Attack Analysis - 7 Systems"
  echo "========================================================================"
  echo "Evidence: $EVIDENCE_BASE"
  echo "Output: $OUTPUT_BASE"
  echo ""
  echo "Systems to analyze:"
  for system in "${ANALYSIS_ORDER[@]}"; do
    echo "  - $system (${SYSTEMS[$system]})"
  done
  echo ""

  read -p "Start analysis? (y/n) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
  fi

  local start_time
  start_time=$(date +%s)

  # Analyze each system in order
  for system in "${ANALYSIS_ORDER[@]}"; do
    local image_file="${SYSTEMS[$system]}"

    echo ""
    analyze_system "$system" "$image_file" || {
      echo "WARNING: Analysis failed for $system, continuing..."
    }

    # Brief pause between systems
    sleep 2
  done

  local end_time
  end_time=$(date +%s)
  local duration=$((end_time - start_time))

  echo "========================================================================"
  echo "  Analysis Complete"
  echo "========================================================================"
  echo "Total time: $((duration / 60)) minutes $((duration % 60)) seconds"
  echo ""
  echo "Results directory: $OUTPUT_BASE"
  echo ""
  echo "Next steps:"
  echo "  1. Review findings: ls -lh $OUTPUT_BASE/*/findings.json"
  echo "  2. Generate summary: python -m sift_find_evil.reporting.multi_system_summary $OUTPUT_BASE"
  echo "  3. Update documentation: Update ACCURACY_REPORT.md and PERFORMANCE_BENCHMARK.md"
  echo ""
}

# Run main
main
