# operatorScript

## 默认使用

```bash
  ./collect.sh \
    --business-time-config ./business_time_config.yaml \
    --resource-history-days "$d" \
    --query-time-range-days "$d" \
    --vm-service "vmselect-vmcluster" \
    --vm-namespace "monitor-platform" \
    --output-dir "./migration_report_${d}"
```

## 参数

```bash
Usage: ./collect.sh [options]

Required options:
  --business-time-config PATH        Business table time column config file (YAML/JSON)

Optional options:
  --ck-user USER                     ClickHouse user (default "root" or CK_USER)
  --ck-password PASSWORD             ClickHouse password (or set CK_PASSWORD; default from k8s secret root)
  --ck-database-business NAME        Business database name (default "business" or CK_DATABASE_BUSINESS)
  --bucket-interval-minutes MINS     Bucket interval for time series stats (default 30 or BUCKET_INTERVAL_MINUTES)
  --resource-history-days DAYS       Lookback window for node metrics and query_log stats (default 30 or RESOURCE_HISTORY_DAYS)
  --query-time-range-days DAYS       Lookback window for time range stats (default 30 or QUERY_TIME_RANGE_DAYS)
  --query-time-range-max-threads N   max_threads for time range query (default 2 or QUERY_TIME_RANGE_MAX_THREADS)
  --query-time-range-max-seconds N   max_execution_time seconds (default 300 or QUERY_TIME_RANGE_MAX_SECONDS)
  --ck-k8s-namespace NAME            Kubernetes namespace containing the ClickHouse pod (ck or set CK_K8S_NAMESPACE)
  --ck-k8s-pod POD                   ClickHouse pod name to exec into (ck or set CK_K8S_POD)
  --ck-cluster-name NAME             ClickHouse cluster name for clusterAllReplicas queries
  --ck-helm-namespace NAME           Namespace to search for Helm releases (default "ck" or CK_HELM_NAMESPACE)
  --vm-service NAME                  VMSelect headless Service name (default "vmselect-vmcluster" or VM_SERVICE)
  --vm-namespace NAME                Namespace where VictoriaMetrics runs (default "monitor-platform" or VM_NAMESPACE)
  --vm-port PORT                     VMSelect port (default 8481 or VM_PORT)
  --vm-tenant-id ID                  VictoriaMetrics tenant/account ID (default 0 or VM_TENANT_ID)
  --vm-bucket-interval-minutes MINS  VM downsample bucket size (default 60 or VM_BUCKET_INTERVAL_MINUTES)
  --vm-rate-window DURATION          PromQL rate() window (default 5m or VM_RATE_WINDOW)
  --vm-node-selector SELECTOR        Selector snippet injected into node-level PromQL
  --vm-ck-pod-selector SELECTOR      Selector snippet injected into CK pod PromQL
  --chi-name NAME                    ClickHouseInstallation name (default "pro" or CHI_NAME)
  --compress-output true|false       Whether to tar.gz the final output directory (default true or COMPRESS_OUTPUT)
  --debug true|false                 Enable debug collectors (default false or DEBUG)
  --output-dir PATH                  Custom output directory (default ./output)

Environment variables listed in the options above act as defaults for the options above.
The script prints the aggregated JSON payload to stdout once all collectors finish.
```
