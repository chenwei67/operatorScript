#!/usr/bin/env bash
set -euo pipefail
days=(1 3 7 15 30 60)
for d in "${days[@]}"; do
  ./collect.sh \
    --business-time-config ./business_time_config.yaml \
    --resource-history-days "$d" \
    --query-time-range-days "$d" \
    --vm-service "vmselect-vmcluster" \
    --vm-namespace "monitor-platform" \
    --output-dir "./migration_report_${d}"
done
