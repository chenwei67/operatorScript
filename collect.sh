#!/usr/bin/env bash
set -euo pipefail
set +H

# 脚本帮助信息
usage() {
  cat <<'EOF'
Usage: ./collect.sh [options]

Required options:
  --ck-user USER                     ClickHouse user (or set CK_USER)
  --ck-password PASSWORD             ClickHouse password (or set CK_PASSWORD)
  --business-time-config PATH        Business table time column config file (YAML/JSON)

Optional options:
  --ck-database-business NAME        Business database name (default "business" or CK_DATABASE_BUSINESS)
  --bucket-interval-minutes MINS     Bucket interval for time series stats (default 30 or BUCKET_INTERVAL_MINUTES)
  --resource-history-days DAYS       Lookback window for node metrics and query_log stats (default 180 or RESOURCE_HISTORY_DAYS)
  --ck-k8s-namespace NAME            Kubernetes namespace containing the ClickHouse pod (ck or set CK_K8S_NAMESPACE)
  --ck-k8s-pod POD                   ClickHouse pod name to exec into (ck or set CK_K8S_POD)
  --ck-cluster-name NAME             ClickHouse cluster name for clusterAllReplicas queries
  --ck-helm-namespace NAME           Namespace to search for Helm releases (default "ck" or CK_HELM_NAMESPACE)
  --vm-service NAME                  VMSelect headless Service name (default "vmselect-vmcluster" or VM_SERVICE)
  --vm-namespace NAME                Namespace where VictoriaMetrics runs (default "monitor-platform" or VM_NAMESPACE)
  --vm-port PORT                     VMSelect port (default 8481 or VM_PORT)
  --vm-tenant-id ID                  VictoriaMetrics tenant/account ID (default 0 or VM_TENANT_ID)
  --vm-node-selector SELECTOR        Selector snippet injected into node-level PromQL
  --vm-ck-pod-selector SELECTOR      Selector snippet injected into CK pod PromQL
  --chi-name NAME                    ClickHouseInstallation name (default "pro" or CHI_NAME)
  --compress-output true|false       Whether to tar.gz the final output directory (default true or COMPRESS_OUTPUT)
  --output-dir PATH                  Custom output directory (default ./output)

Environment variables listed in the options above act as defaults for the options above.
The script prints the aggregated JSON payload to stdout once all collectors finish.
EOF
}

# 统一的日志输出，报告进度
log() {
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  >&2 echo "[$ts] $*"
}

# 原地刷新日志（不换行），用于显示进度条
log_progress() {
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  >&2 printf "\r[%s] %s\033[K" "$ts" "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    >&2 echo "ERROR: missing required command: $1"
    exit 1
  fi
}

json_escape_string() {
  local str="$1"
  str=${str//\\/\\\\}
  str=${str//\"/\\\"}
  str=${str//$'\n'/\\n}
  str=${str//$'\r'/\\r}
  str=${str//$'\t'/\\t}
  printf '%s' "$str"
}

json_string() {
  printf '"%s"' "$(json_escape_string "$1")"
}

json_number_or_null() {
  local value="$1"
  if [[ -z "$value" || "$value" == "null" || "$value" == '\N' ]]; then
    printf 'null'
  else
    printf '%s' "$value"
  fi
}

json_lines_to_array() {
  local src="$1"
  local dest="$2"
  if [[ ! -s "$src" ]]; then
    printf '[]' >"$dest"
    return
  fi
  awk 'NR==1 {printf "["$0; next} {printf ","$0} END {print "]"}' "$src" >"$dest"
}

CLICKHOUSE_CLIENT_BASE=()
CK_USER="${CK_USER:-}"
CK_PASSWORD="${CK_PASSWORD:-}"
CK_DATABASE_BUSINESS="${CK_DATABASE_BUSINESS:-business}"
BUCKET_INTERVAL_MINUTES="${BUCKET_INTERVAL_MINUTES:-30}"
RESOURCE_HISTORY_DAYS="${RESOURCE_HISTORY_DAYS:-180}"
COMPRESS_OUTPUT="${COMPRESS_OUTPUT:-true}"
OUTPUT_DIR="${OUTPUT_DIR:-}"
BUSINESS_TIME_CONFIG="${BUSINESS_TIME_CONFIG:-}"
VM_SERVICE="${VM_SERVICE:-vmselect-vmcluster}"
VM_NAMESPACE="${VM_NAMESPACE:-monitor-platform}"
VM_PORT="${VM_PORT:-8481}"
VM_TENANT_ID="${VM_TENANT_ID:-0}"
VM_NODE_SELECTOR="${VM_NODE_SELECTOR:-}"
VM_CK_POD_SELECTOR="${VM_CK_POD_SELECTOR:-}"
CK_HELM_NAMESPACE="${CK_HELM_NAMESPACE:-ck}"
CK_K8S_NAMESPACE="${CK_K8S_NAMESPACE:-ck}"
CK_K8S_POD="${CK_K8S_POD:-chi-pro-xdr-ck-0-0-0}"
CK_CLUSTER_NAME="${CK_CLUSTER_NAME:-xdr-ck}"
CHI_NAME="${CHI_NAME:-pro}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ck-user)
      CK_USER="$2"
      shift 2
      ;;
    --ck-password)
      CK_PASSWORD="$2"
      shift 2
      ;;
    --ck-database-business)
      CK_DATABASE_BUSINESS="$2"
      shift 2
      ;;
    --bucket-interval-minutes)
      BUCKET_INTERVAL_MINUTES="$2"
      shift 2
      ;;
    --resource-history-days)
      RESOURCE_HISTORY_DAYS="$2"
      shift 2
      ;;
    --compress-output)
      COMPRESS_OUTPUT="$2"
      shift 2
      ;;
    --ck-helm-namespace)
      CK_HELM_NAMESPACE="$2"
      shift 2
      ;;
    --ck-k8s-namespace)
      CK_K8S_NAMESPACE="$2"
      shift 2
      ;;
    --ck-k8s-pod)
      CK_K8S_POD="$2"
      shift 2
      ;;
    --business-time-config)
      BUSINESS_TIME_CONFIG="$2"
      shift 2
      ;;
    --vm-service)
      VM_SERVICE="$2"
      shift 2
      ;;
    --vm-namespace)
      VM_NAMESPACE="$2"
      shift 2
      ;;
    --vm-port)
      VM_PORT="$2"
      shift 2
      ;;
    --vm-tenant-id)
      VM_TENANT_ID="$2"
      shift 2
      ;;
    --vm-node-selector)
      VM_NODE_SELECTOR="$2"
      shift 2
      ;;
    --vm-ck-pod-selector)
      VM_CK_POD_SELECTOR="$2"
      shift 2
      ;;
    --ck-cluster-name)
      CK_CLUSTER_NAME="$2"
      shift 2
      ;;
    --chi-name)
      CHI_NAME="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      >&2 echo "ERROR: unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$CK_USER" ]]; then
  >&2 echo "ERROR: --ck-user or CK_USER is required"
  exit 1
fi
if [[ -z "$CK_PASSWORD" ]]; then
  >&2 echo "ERROR: --ck-password or CK_PASSWORD is required"
  exit 1
fi
if [[ -z "$BUSINESS_TIME_CONFIG" ]]; then
  >&2 echo "ERROR: --business-time-config or BUSINESS_TIME_CONFIG is required"
  exit 1
fi
if [[ -z "$CK_K8S_NAMESPACE" ]]; then
  >&2 echo "ERROR: --ck-k8s-namespace or CK_K8S_NAMESPACE is required"
  exit 1
fi
if [[ -z "$CK_K8S_POD" ]]; then
  >&2 echo "ERROR: --ck-k8s-pod or CK_K8S_POD is required"
  exit 1
fi
if [[ -z "$CK_CLUSTER_NAME" ]]; then
  >&2 echo "ERROR: --ck-cluster-name or CK_CLUSTER_NAME is required"
  exit 1
fi
if [[ ! -f "$BUSINESS_TIME_CONFIG" ]]; then
  >&2 echo "ERROR: business time config file not found: $BUSINESS_TIME_CONFIG"
  exit 1
fi

# 组装 VictoriaMetrics Base URL (Cluster Mode)
# 格式: http://{host}:{port}/select/{accountID}/prometheus
# 后续函数会自动追加 /api/v1/query，最终形成 /select/{tenant}/prometheus/api/v1/query
VM_BASE_URL="http://${VM_SERVICE}-0.${VM_SERVICE}.${VM_NAMESPACE}.svc.cluster.local:${VM_PORT}/select/${VM_TENANT_ID}/prometheus"
log "Configured VictoriaMetrics URL: $VM_BASE_URL"

require_cmd kubectl
require_cmd helm
require_cmd awk
require_cmd sed
require_cmd grep
require_cmd curl
require_cmd date
require_cmd sort
require_cmd head
require_cmd tail
require_cmd cut

VM_ENABLED="true"
VM_BASE_URL_TRIMMED="${VM_BASE_URL%/}"
if ! curl -sS --fail --get --data-urlencode "query=1" "${VM_BASE_URL_TRIMMED}/api/v1/query" >/dev/null 2>&1; then
  log "WARNING: VictoriaMetrics is not reachable at $VM_BASE_URL. Skipping VM-based collectors."
  VM_ENABLED="false"
fi

if ! [[ "$BUCKET_INTERVAL_MINUTES" =~ ^[0-9]+$ ]]; then
  >&2 echo "ERROR: --bucket-interval-minutes must be an integer"
  exit 1
fi
if ! [[ "$RESOURCE_HISTORY_DAYS" =~ ^[0-9]+$ ]]; then
  >&2 echo "ERROR: --resource-history-days must be an integer"
  exit 1
fi
if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$(pwd)/output"
fi
# 准备输出目录结构：主目录 + 各种 timeseries 子目录
mkdir -p "$OUTPUT_DIR"
TIMESERIES_DIR="$OUTPUT_DIR/timeseries"
BUSINESS_WRITES_DIR="$TIMESERIES_DIR/business_table_writes"
BUSINESS_QUERY_LOG_WRITES_DIR="$TIMESERIES_DIR/query_log_writes"
BUSINESS_QUERY_LOG_READS_DIR="$TIMESERIES_DIR/query_log_reads"
SNAPSHOTS_DIR="$OUTPUT_DIR/snapshots"
mkdir -p "$BUSINESS_WRITES_DIR" "$BUSINESS_QUERY_LOG_WRITES_DIR" "$BUSINESS_QUERY_LOG_READS_DIR" "$SNAPSHOTS_DIR"

BUCKET_INTERVAL_MINUTES=$((BUCKET_INTERVAL_MINUTES))
RESOURCE_HISTORY_DAYS=$((RESOURCE_HISTORY_DAYS))
(( BUCKET_INTERVAL_MINUTES <= 0 )) && BUCKET_INTERVAL_MINUTES=30
(( RESOURCE_HISTORY_DAYS <= 0 )) && RESOURCE_HISTORY_DAYS=30
RESOURCE_HISTORY_MINUTES=$((RESOURCE_HISTORY_DAYS * 24 * 60))
if (( RESOURCE_HISTORY_MINUTES < BUCKET_INTERVAL_MINUTES )); then
  RESOURCE_HISTORY_MINUTES=$BUCKET_INTERVAL_MINUTES
fi
VM_BUCKET_INTERVAL_MINUTES=60
VM_BUCKET_INTERVAL_MINUTES=$((VM_BUCKET_INTERVAL_MINUTES))
(( VM_BUCKET_INTERVAL_MINUTES <= 0 )) && VM_BUCKET_INTERVAL_MINUTES=60

TMP_DIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

CLICKHOUSE_CLIENT_BASE=(
  kubectl exec -i -n "$CK_K8S_NAMESPACE" "$CK_K8S_POD" --
  clickhouse-client
  --user "$CK_USER"
  --password "$CK_PASSWORD"
  --param_CK_DATABASE_BUSINESS "$CK_DATABASE_BUSINESS"
  --param_bucket_interval_minutes "$BUCKET_INTERVAL_MINUTES"
  --param_resource_history_days "$RESOURCE_HISTORY_DAYS"
)

run_clickhouse_json_lines() {
  local sql="$1"
  local outfile="$2"
  if ! "${CLICKHOUSE_CLIENT_BASE[@]}" --format JSONEachRow --query "$sql" < /dev/null >"$outfile" 2>"$TMP_DIR/ch_err.log"; then
    >&2 echo "ERROR: ClickHouse query failed:"
    >&2 sed 's/^/  /' "$TMP_DIR/ch_err.log"
    return 1
  fi
}

run_clickhouse_array_query() {
  local sql="$1"
  local outfile="$2"
  local tmp
  tmp=$(mktemp "$TMP_DIR/ch_rows.XXXXXX")
  if run_clickhouse_json_lines "$sql" "$tmp"; then
    json_lines_to_array "$tmp" "$outfile"
  else
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
}

run_clickhouse_append_lines() {
  local sql="$1"
  local outfile="$2"
  local tmp
  tmp=$(mktemp "$TMP_DIR/ch_rows.XXXXXX")
  if run_clickhouse_json_lines "$sql" "$tmp"; then
    cat "$tmp" >>"$outfile"
  fi
  rm -f "$tmp"
}

run_clickhouse_single_tsv() {
  local sql="$1"
  "${CLICKHOUSE_CLIENT_BASE[@]}" --format TabSeparated --query "$sql" < /dev/null 2>"$TMP_DIR/ch_err.log"
}

ck_has_column() {
  local db="$1"
  local table="$2"
  local column="$3"
  local sql
  sql=$(cat <<SQL
SELECT count() > 0
FROM system.columns
WHERE database = '$db' AND table = '$table' AND name = '$column'
SQL
)
  local out
  out=$(run_clickhouse_single_tsv "$sql" 2>/dev/null | head -n1 | tr -d '\r' || true)
  [[ "$out" == "1" ]]
}

ck_has_function() {
  local fn="$1"
  local sql
  sql=$(cat <<SQL
SELECT count() > 0
FROM system.functions
WHERE name = '$fn'
SQL
)
  local out
  out=$(run_clickhouse_single_tsv "$sql" 2>/dev/null | head -n1 | tr -d '\r' || true)
  [[ "$out" == "1" ]]
}

# 执行 ClickHouse 查询并写入 CSV
run_clickhouse_to_csv() {
  local sql="$1"
  local outfile="$2"
  if ! "${CLICKHOUSE_CLIENT_BASE[@]}" --format CSVWithNames --query "$sql" < /dev/null >"$outfile" 2>"$TMP_DIR/ch_err.log"; then
    >&2 echo "ERROR: ClickHouse CSV query failed:"
    >&2 sed 's/^/  /' "$TMP_DIR/ch_err.log"
    return 1
  fi
}

# 将库表名转换为安全的文件名
sanitize_for_filename() {
  local name="${1//\//_}"
  printf '%s' "$name" | sed 's/[^A-Za-z0-9._-]/_/g'
}

# 将包含 database,table 的 CSV 拆分成按表分文件
split_csv_by_table() {
  local src="$1"
  local dest_dir="$2"
  mkdir -p "$dest_dir"
  if [[ ! -s "$src" ]]; then
    return
  fi
  local header
  header=$(head -n1 "$src")
  if [[ -z "$header" ]]; then
    return
  fi
  awk -v dest="$dest_dir" -v header="$header" '
BEGIN {FS=","; OFS=","}
NR==1 {next}
{
  db=$1; tbl=$2;
  gsub(/"/, "", db); gsub(/"/, "", tbl);
  key=db "." tbl
  gsub(/[^A-Za-z0-9._-]/, "_", key)
  file = dest "/" key ".csv"
  if (!(file in seen)) {
    print header > file
    seen[file]=1
  }
  print $0 >> file
}' "$src"
}

# 解析 business_time_config，输出 database/table/column/类型等
parse_business_time_config() {
  local config="$1"
  local output="$2"
  : >"$output"
  awk -v OUT="$output" '
  function trim(str) {
    gsub(/^[[:space:]"'\''`]+|[[:space:]"'\''`,]+$/, "", str)
    return str
  }
  function flush_entry() {
    if (db != "" && tbl != "" && col != "") {
      printf "%s\t%s\t%s\t%s\t%s\n", db, tbl, col, typ, fmt >> OUT
    }
    db=""; tbl=""; col=""; typ=""; fmt=""
  }
  /^[[:space:]]*#/ {next}
  /^[[:space:]]*$/ {next}
  NR==1 {
    if ($0 ~ /^[[:space:]]*\[/ || $0 ~ /^[[:space:]]*\{/) {
      mode="json"
    } else {
      mode="yaml"
    }
  }
  {
    line=$0
    if (mode == "json") {
      gsub(/[\{\}\[\],]/, "", line)
    } else {
      if (line ~ /^[[:space:]]*-\s*$/) {
        flush_entry()
        next
      }
      if (line ~ /^[[:space:]]*-\s*/) {
        flush_entry()
        sub(/^[[:space:]]*-\s*/, "", line)
      }
    }
    if (line ~ /:/) {
      split(line, arr, ":")
      key=arr[1]
      value=substr(line, index(line, ":") + 1)
      key=trim(tolower(key))
      value=trim(value)
      if (key == "database") {
        db=value
      } else if (key == "table") {
        tbl=value
      } else if (key == "time_column") {
        col=value
      } else if (key == "time_type") {
        typ=value
      } else if (key == "time_format") {
        fmt=value
      }
    }
    if (mode == "json" && index($0, "}") > 0) {
      flush_entry()
    }
  }
  END {
    flush_entry()
  }
  ' "$config"
  if [[ ! -s "$output" ]]; then
    >&2 echo "ERROR: failed to parse business time config"
    exit 1
  fi
}

build_time_expression() {
  local column_ident="$1"
  local declared_type="$2"
  local time_format="$3"
  local column_ref="\"$column_ident\""
  local expr="$column_ref"
  local type_lower
  type_lower=$(printf '%s' "$declared_type" | tr '[:upper:]' '[:lower:]')
  case "$type_lower" in
    ""|"datetime"|"datetime64")
      expr="$column_ref"
      ;;
    int64_unix_seconds|int64seconds|unix_seconds|timestamp|timestamp_seconds|int64)
      expr="toDateTime($column_ref)"
      ;;
    int64_unix_milliseconds|int64milliseconds|unix_milliseconds|timestamp_ms|int64ms)
      expr="toDateTime($column_ref / 1000)"
      ;;
    int64_unix_microseconds|int64microseconds|unix_microseconds|timestamp_us|int64us)
      expr="toDateTime($column_ref / 1000000)"
      ;;
    int64_unix_nanoseconds|int64nanoseconds|unix_nanoseconds|timestamp_ns|int64ns)
      expr="toDateTime($column_ref / 1000000000)"
      ;;
    string_formatted)
      # parseDateTimeExact is unavailable on older ClickHouse versions (e.g., 23.2).
      # Use parseDateTimeBestEffort for broader compatibility.
      expr="parseDateTimeBestEffort($column_ref)"
      ;;
    string|varchar|text)
      expr="parseDateTimeBestEffort($column_ref)"
      ;;
    *)
      expr="$column_ref"
      ;;
  esac
  printf '%s' "$expr"
}

BUSINESS_TIME_TARGETS_FILE="$TMP_DIR/business_time_targets.tsv"
log "Parsing business time config from $BUSINESS_TIME_CONFIG"
parse_business_time_config "$BUSINESS_TIME_CONFIG" "$BUSINESS_TIME_TARGETS_FILE"

# 准备 Helm 配置输出目录
HELM_OUTPUT_DIR="$OUTPUT_DIR/helm"
mkdir -p "$HELM_OUTPUT_DIR"
log "Collecting Helm release values from namespace: $CK_HELM_NAMESPACE"
# 获取该命名空间下所有 Release 名称 (-q 只输出名字)
if RELEASES=$(helm list -n "$CK_HELM_NAMESPACE" -q 2>/dev/null); then
  if [[ -z "$RELEASES" ]]; then
    log "WARNING: No Helm releases found in namespace: $CK_HELM_NAMESPACE"
  else
    for RELEASE in $RELEASES; do
      SAFE_NAME=$(sanitize_for_filename "$RELEASE")
      OUT_YAML="$HELM_OUTPUT_DIR/${SAFE_NAME}.yaml"

      log "  -> Exporting Helm release: $RELEASE to $OUT_YAML"

      # 导出用户自定义配置 (User-supplied values)
      # 如果需要导出所有计算后的值，可以使用 --all，但通常用户配置更有分析价值
      if ! helm get values "$RELEASE" -n "$CK_HELM_NAMESPACE" >"$OUT_YAML" 2>"$TMP_DIR/helm_err.log"; then
        log "WARNING: Failed to get values for release $RELEASE"
      fi
    done
  fi
else
  log "ERROR: 'helm list' failed. Check kubectl context and permissions."
fi

# 集群基础信息统计
log "Querying ClickHouse version"
# 查询 CK 版本
CK_VERSION_VALUE=$("${CLICKHOUSE_CLIENT_BASE[@]}" --format TabSeparated --query "SELECT version()" 2>"$TMP_DIR/ch_err.log" | head -n1 | tr -d '\r')

# 使用 kubectl 统计 K8s 节点数量
log "Collecting node count via kubectl"
CLUSTER_NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d '[:space:]')
if [[ -z "$CLUSTER_NODE_COUNT" ]]; then
  log "WARNING: kubectl get nodes failed; default node count to 0"
  CLUSTER_NODE_COUNT="0"
fi

# 获取 ClickHouseInstallation 配置中的分片/副本数
log "Collecting CHI layout (shards/replicas) for CHI: $CHI_NAME"
CHI_SHARDS=""
CHI_REPLICAS=""
CHI_EXPECTED_NODE_COUNT=""
CHI_LAYOUT_RAW=$(kubectl get chi "$CHI_NAME" -n "$CK_K8S_NAMESPACE" -o jsonpath='{.spec.configuration.clusters[0].layout.shardsCount} {.spec.configuration.clusters[0].layout.replicasCount}' 2>/dev/null || true)
if [[ -n "$CHI_LAYOUT_RAW" ]]; then
  read -r CHI_SHARDS CHI_REPLICAS <<<"$CHI_LAYOUT_RAW"
  [[ "$CHI_SHARDS" =~ ^[0-9]+$ ]] || CHI_SHARDS=""
  [[ "$CHI_REPLICAS" =~ ^[0-9]+$ ]] || CHI_REPLICAS=""
else
  log "WARNING: Failed to fetch CHI layout; defaulting to null"
fi
if [[ -n "$CHI_SHARDS" && -n "$CHI_REPLICAS" ]]; then
  CHI_EXPECTED_NODE_COUNT=$((CHI_SHARDS * CHI_REPLICAS))
fi

# 表基础数据采集（全量 + 去重后的物理体积）
log "Collecting table statistics (CSV)"
TABLE_STATS_CSV="$OUTPUT_DIR/table_stats.csv"
# 说明：这里先通过 system.tables 拿到所有表定义（包括空表、Distributed 表等），
# 接着 LEFT JOIN 一个只统计 replica_num=1 的 system.parts 聚合结果，确保既不漏表也不重复统计。
TABLE_STATS_SQL=$(cat <<SQL
SELECT
    t.database,
    t.name AS table,
    t.engine,
    coalesce(p.total_rows, 0) AS total_rows,
    coalesce(p.bytes_on_disk, 0) AS compressed_size_bytes,
    coalesce(p.data_uncompressed_bytes, 0) AS uncompressed_size_bytes
FROM
(
    SELECT DISTINCT database, name, engine
    FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.tables)
    WHERE database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA')
) AS t
LEFT JOIN
(
    SELECT
        database,
        table,
        sum(rows) AS total_rows,
        sum(bytes_on_disk) AS bytes_on_disk,
        sum(data_uncompressed_bytes) AS data_uncompressed_bytes
    FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.parts)
    WHERE active = 1
      AND database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA')
      AND hostName() IN (
          SELECT hostName()
          FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.clusters)
          WHERE cluster = '${CK_CLUSTER_NAME}' AND replica_num = 1
      )
    GROUP BY database, table
) AS p
ON t.database = p.database AND t.name = p.table
ORDER BY compressed_size_bytes DESC, t.database, t.name
SQL
)
run_clickhouse_to_csv "$TABLE_STATS_SQL" "$TABLE_STATS_CSV"

# ClickHouse 存储卷（system.disks）
log "Collecting cluster-wide storage volume info (system.disks)"
STORAGE_VOLUMES_CSV="$SNAPSHOTS_DIR/cluster_storage_volumes.csv"
STORAGE_SQL=$(cat <<SQL
SELECT
    hostName() AS node_host,
    name,
    path,
    total_space AS total_space_bytes,
    free_space AS free_space_bytes,
    keep_free_space AS keep_free_space_bytes
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.disks)
ORDER BY node_host, total_space_bytes DESC
SQL
)
run_clickhouse_to_csv "$STORAGE_SQL" "$STORAGE_VOLUMES_CSV"

log "Collecting K8s cluster node inventory"
K8S_NODES_CSV="$SNAPSHOTS_DIR/cluster_k8s_nodes.csv"
echo "name,internal_ip,os_image,kernel_version,cpu_capacity,memory_capacity,cpu_allocatable,memory_allocatable,creation_timestamp" > "$K8S_NODES_CSV"
if ! kubectl get nodes -o jsonpath='{range .items[*]}"{.metadata.name}","{.status.addresses[?(@.type=="InternalIP")].address}","{.status.nodeInfo.osImage}","{.status.nodeInfo.kernelVersion}","{.status.capacity.cpu}","{.status.capacity.memory}","{.status.allocatable.cpu}","{.status.allocatable.memory}","{.metadata.creationTimestamp}"{"\n"}{end}' >> "$K8S_NODES_CSV" 2>"$TMP_DIR/k8s_nodes.log"; then
  log "WARNING: Failed to collect node inventory via kubectl"
fi


# business 表 TTL 信息输出为 CSV，同时提取 TTL 数值
log "Collecting business TTL metadata (CSV)"
BUSINESS_TTL_CSV="$OUTPUT_DIR/business_ttl.csv"
run_clickhouse_to_csv $'SELECT
  database,
  table,
  ttl_expression,
  ttl_value
FROM (
  SELECT
    database,
    table,
    regexpExtract(engine_full, \'(TTL.+)SETTINGS\', 1) AS ttl_expression,
    toInt32OrNull(regexpExtract(engine_full, \'toInterval(?:Year|Month|Week|Day|Hour|Minute|Second)\\((\\d+)\\)\', 1)) AS ttl_value
  FROM system.tables
  WHERE
    database = {CK_DATABASE_BUSINESS:String}
    AND engine LIKE \'%MergeTree\'
)
ORDER BY database, table' "$BUSINESS_TTL_CSV"

# 所有表 schema 信息输出到 CSV，方便表格查看
log "Collecting table schema (CSV)"
TABLE_SCHEMA_CSV="$OUTPUT_DIR/table_schema.csv"
run_clickhouse_to_csv $'SELECT database, table, name AS column, type, default_kind, default_expression FROM system.columns WHERE database NOT IN (\'system\', \'information_schema\', \'INFORMATION_SCHEMA\') ORDER BY database, table, column' "$TABLE_SCHEMA_CSV"

log "Collecting system.settings (CSV)"
SYSTEM_SETTINGS_CSV="$SNAPSHOTS_DIR/system_settings.csv"
if ! run_clickhouse_to_csv "SELECT name, value, changed, description FROM system.settings ORDER BY name" "$SYSTEM_SETTINGS_CSV"; then
  log "WARNING: Failed to collect system.settings"
fi

log "Collecting system.build_options (CSV)"
SYSTEM_BUILD_OPTIONS_CSV="$SNAPSHOTS_DIR/system_build_options.csv"
if ! run_clickhouse_to_csv "SELECT name, value FROM system.build_options ORDER BY name" "$SYSTEM_BUILD_OPTIONS_CSV"; then
  log "WARNING: Failed to collect system.build_options"
fi

# business 表写入按时间切片输出（每个表一个 CSV）
log "Collecting business table write statistics per time column"
# 为每个 business 表执行一次分桶统计并生成独立 CSV
while IFS=$'\t' read -r BT_DB BT_TABLE BT_COLUMN BT_TYPE BT_FORMAT; do
  [[ -z "$BT_DB" || -z "$BT_TABLE" || -z "$BT_COLUMN" ]] && continue
  DB_IDENT=$(printf '%s' "$BT_DB" | sed 's/"/""/g')
  TABLE_IDENT=$(printf '%s' "$BT_TABLE" | sed 's/"/""/g')
  COL_IDENT=$(printf '%s' "$BT_COLUMN" | sed 's/"/""/g')
  TIME_EXPR=$(build_time_expression "$COL_IDENT" "$BT_TYPE" "$BT_FORMAT")
  DB_DIR="$BUSINESS_WRITES_DIR/$(sanitize_for_filename "$BT_DB")"
  mkdir -p "$DB_DIR"
  TABLE_SAFE=$(sanitize_for_filename "$BT_TABLE")
  OUT_CSV="$DB_DIR/${TABLE_SAFE}.csv"
  log "  -> $BT_DB.$BT_TABLE -> $OUT_CSV"
  SQL=$(cat <<SQL
SELECT
  toStartOfInterval($TIME_EXPR, INTERVAL {bucket_interval_minutes:Int32} MINUTE) AS start_time,
  toStartOfInterval($TIME_EXPR, INTERVAL {bucket_interval_minutes:Int32} MINUTE) + INTERVAL {bucket_interval_minutes:Int32} MINUTE AS end_time,
  count() AS rows
FROM "$DB_IDENT"."$TABLE_IDENT"
WHERE $TIME_EXPR >= now() - INTERVAL {resource_history_days:Int32} DAY
GROUP BY start_time, end_time
ORDER BY start_time
SQL
)
  run_clickhouse_to_csv "$SQL" "$OUT_CSV"
done <"$BUSINESS_TIME_TARGETS_FILE"

# query_log 流量画像（写入 + 读取）
log "Collecting query_log metrics for Inserts"
# 写入类 query_log 先生成整表 CSV 再拆成每表文件
BUSINESS_QUERY_LOG_WRITES_TMP="$TMP_DIR/business_query_log_writes.csv"
BUSINESS_QUERY_LOG_WRITES_SQL=$(cat <<SQL
SELECT
  arrayElement(databases, idx) AS database,
  arrayElement(tables, idx) AS table,
  toStartOfInterval(event_time, INTERVAL {bucket_interval_minutes:Int32} MINUTE) AS start_time,
  toStartOfInterval(event_time, INTERVAL {bucket_interval_minutes:Int32} MINUTE) + INTERVAL {bucket_interval_minutes:Int32} MINUTE AS end_time,
  count() AS queries,
  sum(written_rows) AS rows
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.query_log)
ARRAY JOIN arrayEnumerate(databases) AS idx
WHERE
  event_time >= now() - INTERVAL {resource_history_days:Int32} DAY
  AND type = 'QueryFinish'
  AND is_initial_query = 1
  AND query_kind = 'Insert'
  AND arrayElement(databases, idx) = {CK_DATABASE_BUSINESS:String}
  AND idx <= length(tables)
GROUP BY database, table, start_time, end_time
ORDER BY database, table, start_time
SQL
)
run_clickhouse_to_csv "$BUSINESS_QUERY_LOG_WRITES_SQL" "$BUSINESS_QUERY_LOG_WRITES_TMP"
split_csv_by_table "$BUSINESS_QUERY_LOG_WRITES_TMP" "$BUSINESS_QUERY_LOG_WRITES_DIR"

log "Collecting query_log metrics for Selects"
# 读取类 query_log 分表拆分
BUSINESS_QUERY_LOG_READS_TMP="$TMP_DIR/business_query_log_reads.csv"
BUSINESS_QUERY_LOG_READS_SQL=$(cat <<SQL
SELECT
  arrayElement(databases, idx) AS database,
  arrayElement(tables, idx) AS table,
  toStartOfInterval(event_time, INTERVAL {bucket_interval_minutes:Int32} MINUTE) AS start_time,
  toStartOfInterval(event_time, INTERVAL {bucket_interval_minutes:Int32} MINUTE) + INTERVAL {bucket_interval_minutes:Int32} MINUTE AS end_time,
  count() AS queries
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.query_log)
ARRAY JOIN arrayEnumerate(databases) AS idx
WHERE
  event_time >= now() - INTERVAL {resource_history_days:Int32} DAY
  AND type = 'QueryFinish'
  AND is_initial_query = 1
  AND query_kind = 'Select'
  AND arrayElement(databases, idx) = {CK_DATABASE_BUSINESS:String}
  AND idx <= length(tables)
GROUP BY database, table, start_time, end_time
ORDER BY database, table, start_time
SQL
)
run_clickhouse_to_csv "$BUSINESS_QUERY_LOG_READS_SQL" "$BUSINESS_QUERY_LOG_READS_TMP"
split_csv_by_table "$BUSINESS_QUERY_LOG_READS_TMP" "$BUSINESS_QUERY_LOG_READS_DIR"

log "Collecting query_log written bytes timeseries (CSV)"
QUERY_LOG_WRITTEN_BYTES_CSV="$TIMESERIES_DIR/query_log_written_bytes_timeseries.csv"
if ck_has_column "system" "query_log" "written_bytes"; then
  QUERY_LOG_WRITTEN_BYTES_SQL=$(cat <<SQL
SELECT
  toStartOfInterval(event_time, INTERVAL {bucket_interval_minutes:Int32} MINUTE) AS start_time,
  toStartOfInterval(event_time, INTERVAL {bucket_interval_minutes:Int32} MINUTE) + INTERVAL {bucket_interval_minutes:Int32} MINUTE AS end_time,
  count() AS queries,
  sum(written_rows) AS written_rows,
  sum(written_bytes) AS written_bytes,
  'query_log.written_bytes' AS method
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.query_log)
WHERE
  event_time >= now() - INTERVAL {resource_history_days:Int32} DAY
  AND type = 'QueryFinish'
  AND is_initial_query = 1
  AND query_kind = 'Insert'
  AND has(databases, {CK_DATABASE_BUSINESS:String})
GROUP BY start_time, end_time
ORDER BY start_time
SQL
)
  if ! run_clickhouse_to_csv "$QUERY_LOG_WRITTEN_BYTES_SQL" "$QUERY_LOG_WRITTEN_BYTES_CSV"; then
    log "WARNING: Failed to collect query_log written_bytes timeseries"
  fi
elif ck_has_column "system" "part_log" "event_type"; then
  PART_LOG_BYTES_EXPR="0"
  if ck_has_column "system" "part_log" "bytes_compressed_on_disk"; then
    PART_LOG_BYTES_EXPR="bytes_compressed_on_disk"
  elif ck_has_column "system" "part_log" "bytes_on_disk"; then
    PART_LOG_BYTES_EXPR="bytes_on_disk"
  fi
  PART_LOG_ROWS_EXPR="0"
  if ck_has_column "system" "part_log" "rows"; then
    PART_LOG_ROWS_EXPR="rows"
  fi
  QUERY_LOG_WRITTEN_BYTES_SQL=$(cat <<SQL
SELECT
  toDateTime(toDate(event_time)) AS start_time,
  toDateTime(toDate(event_time) + 1) AS end_time,
  0 AS queries,
  sumIf($PART_LOG_ROWS_EXPR, event_type = 'NewPart') AS written_rows,
  sumIf($PART_LOG_BYTES_EXPR, event_type = 'NewPart') AS written_bytes,
  'approx.part_log.NewPart' AS method
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.part_log)
WHERE
  event_time >= now() - INTERVAL {resource_history_days:Int32} DAY
  AND database = {CK_DATABASE_BUSINESS:String}
GROUP BY start_time, end_time
ORDER BY start_time
SQL
)
  if ! run_clickhouse_to_csv "$QUERY_LOG_WRITTEN_BYTES_SQL" "$QUERY_LOG_WRITTEN_BYTES_CSV"; then
    log "WARNING: Failed to collect approximate written_bytes from system.part_log"
  fi
else
  QUERY_LOG_WRITTEN_BYTES_SQL=$(cat <<SQL
SELECT
  toDateTime(toDate(modification_time)) AS start_time,
  toDateTime(toDate(modification_time) + 1) AS end_time,
  0 AS queries,
  0 AS written_rows,
  sum(bytes_on_disk) AS written_bytes,
  'approx.parts.bytes_on_disk_by_modification_time' AS method
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.parts)
WHERE
  active = 1
  AND database = {CK_DATABASE_BUSINESS:String}
  AND modification_time >= now() - INTERVAL {resource_history_days:Int32} DAY
  AND hostName() IN (
      SELECT hostName()
      FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.clusters)
      WHERE cluster = '${CK_CLUSTER_NAME}' AND replica_num = 1
  )
GROUP BY start_time, end_time
ORDER BY start_time
SQL
)
  if ! run_clickhouse_to_csv "$QUERY_LOG_WRITTEN_BYTES_SQL" "$QUERY_LOG_WRITTEN_BYTES_CSV"; then
    log "WARNING: Failed to collect approximate written_bytes from system.parts"
  fi
fi

# query_log 延迟/读写字节画像（用于做迁移前的线上体验基线）
log "Collecting query_log latency and bytes metrics (CSV)"
QUERY_LOG_LATENCY_CSV="$TIMESERIES_DIR/query_log_latency_timeseries.csv"
echo "query_kind,start_time,end_time,queries,p50_ms,p95_ms,p99_ms,avg_ms,sum_read_bytes,max_memory_usage_bytes" >"$QUERY_LOG_LATENCY_CSV"
if ck_has_column "system" "query_log" "query_duration_ms"; then
  READ_BYTES_EXPR="0"
  if ck_has_column "system" "query_log" "read_bytes"; then
    READ_BYTES_EXPR="read_bytes"
  fi
  MEMORY_USAGE_EXPR="0"
  if ck_has_column "system" "query_log" "memory_usage"; then
    MEMORY_USAGE_EXPR="memory_usage"
  fi
  QUERY_LOG_LATENCY_SQL=$(cat <<SQL
SELECT
  query_kind,
  toStartOfInterval(event_time, INTERVAL {bucket_interval_minutes:Int32} MINUTE) AS start_time,
  toStartOfInterval(event_time, INTERVAL {bucket_interval_minutes:Int32} MINUTE) + INTERVAL {bucket_interval_minutes:Int32} MINUTE AS end_time,
  count() AS queries,
  quantile(0.50)(query_duration_ms) AS p50_ms,
  quantile(0.95)(query_duration_ms) AS p95_ms,
  quantile(0.99)(query_duration_ms) AS p99_ms,
  avg(query_duration_ms) AS avg_ms,
  sum($READ_BYTES_EXPR) AS sum_read_bytes,
  max($MEMORY_USAGE_EXPR) AS max_memory_usage_bytes
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.query_log)
WHERE
  event_time >= now() - INTERVAL {resource_history_days:Int32} DAY
  AND type = 'QueryFinish'
  AND is_initial_query = 1
  AND query_kind IN ('Select', 'Insert')
  AND has(databases, {CK_DATABASE_BUSINESS:String})
GROUP BY query_kind, start_time, end_time
ORDER BY query_kind, start_time
SQL
)
  if ! run_clickhouse_to_csv "$QUERY_LOG_LATENCY_SQL" "$QUERY_LOG_LATENCY_CSV"; then
    log "WARNING: Failed to collect query_log latency metrics. Skipping."
  fi
else
  log "WARNING: system.query_log.query_duration_ms not found. Skipping query_log latency metrics."
fi

log "Collecting top slow queries in last 30 days (CSV)"
SLOW_QUERIES_CSV="$OUTPUT_DIR/slow_queries_top.csv"
echo "query_kind,normalized_query,queries,p95_query_duration_ms,avg_query_duration_ms,sum_read_bytes,max_memory_usage_bytes" >"$SLOW_QUERIES_CSV"
if ck_has_column "system" "query_log" "query_duration_ms"; then
  SLOW_QUERY_TOP_N=100
  NORMALIZED_QUERY_EXPR="query"
  if ck_has_column "system" "query_log" "normalized_query"; then
    NORMALIZED_QUERY_EXPR="normalized_query"
  elif ck_has_function "normalizeQuery"; then
    NORMALIZED_QUERY_EXPR="normalizeQuery(query)"
  fi
  READ_BYTES_EXPR="0"
  if ck_has_column "system" "query_log" "read_bytes"; then
    READ_BYTES_EXPR="read_bytes"
  fi
  MEMORY_USAGE_EXPR="0"
  if ck_has_column "system" "query_log" "memory_usage"; then
    MEMORY_USAGE_EXPR="memory_usage"
  fi
  SLOW_QUERIES_SQL=$(cat <<SQL
SELECT
  query_kind,
  $NORMALIZED_QUERY_EXPR AS normalized_query,
  count() AS queries,
  quantile(0.95)(query_duration_ms) AS p95_query_duration_ms,
  avg(query_duration_ms) AS avg_query_duration_ms,
  sum($READ_BYTES_EXPR) AS sum_read_bytes,
  max($MEMORY_USAGE_EXPR) AS max_memory_usage_bytes
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.query_log)
WHERE
  event_time >= now() - INTERVAL 30 DAY
  AND type = 'QueryFinish'
  AND is_initial_query = 1
  AND query_kind = 'Select'
  AND has(databases, {CK_DATABASE_BUSINESS:String})
GROUP BY query_kind, normalized_query
ORDER BY p95_query_duration_ms DESC
LIMIT $SLOW_QUERY_TOP_N
SQL
)
  if ! run_clickhouse_to_csv "$SLOW_QUERIES_SQL" "$SLOW_QUERIES_CSV"; then
    log "WARNING: Failed to collect slow queries"
  fi
else
  log "WARNING: system.query_log.query_duration_ms not found. Skipping slow queries export."
fi

# CK parts/partition 压力快照（用于判断合并压力与迁移风险）
log "Collecting parts and partitions snapshot (CSV)"
PARTS_SNAPSHOT_CSV="$SNAPSHOTS_DIR/cluster_parts_snapshot.csv"
PARTS_SNAPSHOT_SQL=$(cat <<SQL
SELECT
  database,
  table,
  count() AS active_parts,
  uniqExact(partition) AS partitions,
  sum(rows) AS rows,
  sum(bytes_on_disk) AS bytes_on_disk,
  max(bytes_on_disk) AS max_part_bytes_on_disk
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.parts)
WHERE
  active = 1
  AND database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA')
  AND hostName() IN (
      SELECT hostName()
      FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.clusters)
      WHERE cluster = '${CK_CLUSTER_NAME}' AND replica_num = 1
  )
GROUP BY database, table
ORDER BY bytes_on_disk DESC, database, table
SQL
)
if ! run_clickhouse_to_csv "$PARTS_SNAPSHOT_SQL" "$PARTS_SNAPSHOT_CSV"; then
  log "WARNING: Failed to collect parts snapshot."
fi

# CK merges/mutations 快照（用于识别后台任务是否已经很紧）
log "Collecting merges snapshot (CSV)"
MERGES_SNAPSHOT_CSV="$SNAPSHOTS_DIR/cluster_merges_snapshot.csv"
MERGES_SNAPSHOT_SQL=$(cat <<SQL
SELECT
  hostName() AS node_host,
  count() AS merges_running,
  sum(num_parts) AS merging_parts,
  sum(total_size_bytes_compressed) AS merging_bytes_compressed
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.merges)
GROUP BY node_host
ORDER BY merges_running DESC, node_host
SQL
)
if ! run_clickhouse_to_csv "$MERGES_SNAPSHOT_SQL" "$MERGES_SNAPSHOT_CSV"; then
  log "WARNING: Failed to collect merges snapshot."
fi

log "Collecting mutations snapshot (CSV)"
MUTATIONS_SNAPSHOT_CSV="$SNAPSHOTS_DIR/cluster_mutations_snapshot.csv"
MUTATIONS_SNAPSHOT_SQL=$(cat <<SQL
SELECT
  database,
  table,
  count() AS mutations_running,
  sum(is_done = 0) AS mutations_not_done
FROM clusterAllReplicas('${CK_CLUSTER_NAME}', system.mutations)
WHERE is_done = 0
GROUP BY database, table
ORDER BY mutations_not_done DESC, database, table
SQL
)
if ! run_clickhouse_to_csv "$MUTATIONS_SNAPSHOT_SQL" "$MUTATIONS_SNAPSHOT_CSV"; then
  log "WARNING: Failed to collect mutations snapshot."
fi

log "Discovering all cluster nodes via kubectl"
# 获取所有节点的 InternalIP。
# 使用 tr -s '[:space:]' '|' 将所有空白字符（包括换行符和空格）压缩并替换为竖线，防止正则断裂
ALL_NODE_IPS_REGEX=$(kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null | tr -s '[:space:]' '|' || true)
# 去除可能存在的首尾竖线，防止生成 "|10.x" 或 "10.x|" 这种非法正则
ALL_NODE_IPS_REGEX=${ALL_NODE_IPS_REGEX%|}
ALL_NODE_IPS_REGEX=${ALL_NODE_IPS_REGEX#|}
if [[ -n "$ALL_NODE_IPS_REGEX" ]]; then
  log "  -> Found cluster node IPs (Regex): $ALL_NODE_IPS_REGEX"
else
  log "WARNING: Failed to discover node IPs via kubectl. Cluster metrics might be empty."
fi
AUTO_CLUSTER_IP_REGEX=""
if [[ -n "$ALL_NODE_IPS_REGEX" ]]; then
  IFS='|' read -r -a NODE_IP_ARRAY <<<"$ALL_NODE_IPS_REGEX"
  for ip in "${NODE_IP_ARRAY[@]}"; do
    [[ -z "$ip" ]] && continue
    log "    - Node IP: $ip"
    escaped_ip="$ip"
    if [[ -z "$AUTO_CLUSTER_IP_REGEX" ]]; then
      AUTO_CLUSTER_IP_REGEX="${escaped_ip}.*"
    else
      AUTO_CLUSTER_IP_REGEX="${AUTO_CLUSTER_IP_REGEX}|${escaped_ip}.*"
    fi
  done
fi

vm_query_instant_to_file() {
  local promql="$1"
  local eval_ts="$2"
  local outfile="$3"
  local base="${VM_BASE_URL%/}"
  if [[ "$VM_ENABLED" != "true" ]]; then
    printf '{"status":"error","data":{"result":[]}}' >"$outfile"
    return 0
  fi
  if [[ -n "$eval_ts" ]]; then
    curl -sS --fail --get --data-urlencode "query=$promql" --data-urlencode "time=$eval_ts" "$base/api/v1/query" >"$outfile"
  else
    curl -sS --fail --get --data-urlencode "query=$promql" "$base/api/v1/query" >"$outfile"
  fi
}

parse_vm_disk_snapshot() {
  local src="$1"
  local dest="$2"
  : >"$dest"
  tr -d '[:space:]' <"$src" | sed 's/{"metric":/\n{"metric":/g' | sed -n 's/.*"device":"\([^"]\+\)".*"instance":"\([^"]\+\)".*"mountpoint":"\([^"]\+\)".*"value":\[[^,]\+,"\([^"]\+\)"\].*/\2\t\3\t\1\t\4/p' >>"$dest"
  tr -d '[:space:]' <"$src" | sed 's/{"metric":/\n{"metric":/g' | sed -n 's/.*"instance":"\([^"]\+\)".*"device":"\([^"]\+\)".*"mountpoint":"\([^"]\+\)".*"value":\[[^,]\+,"\([^"]\+\)"\].*/\1\t\3\t\2\t\4/p' >>"$dest"
}

log "Collecting cluster-wide detailed disk usage from VictoriaMetrics"
DISK_USAGE_CSV="$SNAPSHOTS_DIR/cluster_node_disk_usage.csv"
echo "node_name,mountpoint,device,total_bytes,free_bytes,used_bytes,used_percent" > "$DISK_USAGE_CSV"
CLUSTER_DISK_SELECTOR=""
if [[ -n "$VM_NODE_SELECTOR" ]]; then
  CLUSTER_DISK_SELECTOR="$VM_NODE_SELECTOR"
elif [[ -n "$AUTO_CLUSTER_IP_REGEX" ]]; then
  CLUSTER_DISK_SELECTOR=$(printf 'instance=~"%s"' "$AUTO_CLUSTER_IP_REGEX")
fi
if [[ -n "$CLUSTER_DISK_SELECTOR" ]]; then
  DISK_FILTER=$(printf 'fstype!~"tmpfs|overlay|shm|autofs|cgroup|nsfs",%s' "$CLUSTER_DISK_SELECTOR")
  DISK_TOTAL_PROMQL="node_filesystem_size_bytes{$DISK_FILTER}"
  DISK_FREE_PROMQL="node_filesystem_free_bytes{$DISK_FILTER}"
  TOTAL_JSON=$(mktemp "$TMP_DIR/disk_total.json.XXXXXX")
  FREE_JSON=$(mktemp "$TMP_DIR/disk_free.json.XXXXXX")
  TOTAL_TSV=$(mktemp "$TMP_DIR/disk_total.tsv.XXXXXX")
  FREE_TSV=$(mktemp "$TMP_DIR/disk_free.tsv.XXXXXX")
  vm_query_instant_to_file "$DISK_TOTAL_PROMQL" "" "$TOTAL_JSON"
  vm_query_instant_to_file "$DISK_FREE_PROMQL" "" "$FREE_JSON"
  parse_vm_disk_snapshot "$TOTAL_JSON" "$TOTAL_TSV"
  sort -u "$TOTAL_TSV" -o "$TOTAL_TSV"
  parse_vm_disk_snapshot "$FREE_JSON" "$FREE_TSV"
  sort -u "$FREE_TSV" -o "$FREE_TSV"
  awk -F'\t' -v OFS=',' '
    FNR==NR { free[$1 SUBSEP $2 SUBSEP $3] = $4; next }
    {
      total = $4
      key = $1 SUBSEP $2 SUBSEP $3
      f_val = (key in free) ? free[key] : 0
      used_val = total - f_val
      used_pct = (total > 0) ? (used_val / total) * 100 : 0
      print $1, $2, $3, total, f_val, used_val, sprintf("%.2f", used_pct)
    }
  ' "$FREE_TSV" "$TOTAL_TSV" >>"$DISK_USAGE_CSV"
  rm -f "$TOTAL_JSON" "$FREE_JSON" "$TOTAL_TSV" "$FREE_TSV"
else
  log "WARNING: No VM node selector or auto-discovered IPs. Skipping disk usage details."
fi

# 节点静态信息与负载快照采集
log "Collecting node hardware snapshot"
HOSTNAME=$(hostname 2>/dev/null || echo "")
SERVER_MODEL=$(cat /sys/class/dmi/id/product_name 2>/dev/null || echo "unknown")
OS_ARCH=$(uname -m 2>/dev/null || echo "")
OS_KERNEL=$(uname -r 2>/dev/null || echo "")
CPU_CORES=$(nproc 2>/dev/null || echo 0)
MEM_TOTAL=$(awk '/MemTotal/ {print $2 * 1024; exit}' /proc/meminfo)
MEM_AVAILABLE=$(awk '/MemAvailable/ {print $2 * 1024; exit}' /proc/meminfo)
DISK_TOTAL=$(df -B1 / | awk 'NR==2 {print $2}')
DISK_USED=$(df -B1 / | awk 'NR==2 {print $3}')
MEM_TOTAL=${MEM_TOTAL:-0}
MEM_AVAILABLE=${MEM_AVAILABLE:-0}
DISK_TOTAL=${DISK_TOTAL:-0}
DISK_USED=${DISK_USED:-0}
if (( MEM_TOTAL > MEM_AVAILABLE )); then
  MEM_USED=$((MEM_TOTAL - MEM_AVAILABLE))
else
  MEM_USED=0
fi
read -r LOAD_1 LOAD_5 LOAD_15 _ < /proc/loadavg 2>/dev/null || {
  LOAD_1=""
  LOAD_5=""
  LOAD_15=""
}
CPU_FLAGS=$(grep -oE ' (avx2|avx512f) ' /proc/cpuinfo 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,/, /g; s/^, //; s/, $//' )
[[ -z "$CPU_FLAGS" ]] && CPU_FLAGS="none"
SWAP_TOTAL=$(awk '/SwapTotal/ {print $2 * 1024; exit}' /proc/meminfo)
SWAP_FREE=$(awk '/SwapFree/ {print $2 * 1024; exit}' /proc/meminfo)
SWAP_TOTAL=${SWAP_TOTAL:-0}
SWAP_FREE=${SWAP_FREE:-0}
if (( SWAP_TOTAL > SWAP_FREE )); then
  SWAP_USED=$((SWAP_TOTAL - SWAP_FREE))
else
  SWAP_USED=0
fi
read -r FD_ALLOC _ FD_MAX < /proc/sys/fs/file-nr 2>/dev/null || {
  FD_ALLOC=0
  FD_MAX=0
}
TCP_IN_USE=$(grep 'TCP:' /proc/net/sockstat 2>/dev/null | awk '{print $3}')
TCP_TIME_WAIT=$(grep 'TCP:' /proc/net/sockstat 2>/dev/null | awk '{print $7}')
TCP_IN_USE=${TCP_IN_USE:-0}
TCP_TIME_WAIT=${TCP_TIME_WAIT:-0}
calc_percentage() {
  local used="$1"
  local total="$2"
  if [[ -z "$used" || -z "$total" || "$total" -le 0 ]]; then
    printf ''
  else
    awk -v u="$used" -v t="$total" 'BEGIN {printf "%.2f", (u/t)*100}'
  fi
}
MEM_USAGE_PERCENT=$(calc_percentage "$MEM_USED" "$MEM_TOTAL")
DISK_USAGE_PERCENT=$(calc_percentage "$DISK_USED" "$DISK_TOTAL")

# 下方为调用 VictoriaMetrics 的辅助函数（封装 PromQL 构造与结果解析）
render_selector_placeholder() {
  local template="$1"
  local rendered="${template//\{\{VM_NODE_SELECTOR\}\}/$VM_NODE_SELECTOR}"
  rendered="${rendered//\{\{VM_CK_POD_SELECTOR\}\}/$VM_CK_POD_SELECTOR}"
  echo "$rendered"
}

vm_query_to_file() {
  local promql="$1"
  local outfile="$2"
  local base="${VM_BASE_URL%/}"
  if [[ "$VM_ENABLED" != "true" ]]; then
    printf '{"status":"error","data":{"result":[]}}' >"$outfile"
    return 0
  fi
  curl -sS --fail --get --data-urlencode "query=$promql" "$base/api/v1/query" >"$outfile"
}

parse_vm_vector_response() {
  local src="$1"
  local dest="$2"
  local label="${3:-instance}"
  : >"$dest"
  tr -d '[:space:]' < "$src" \
    | sed 's/{"metric":/\n{"metric":/g' \
    | sed -n "s/.*\"$label\":\"\([^\"]\+\)\".*\"value\":\[[^,]\+,\"\([^\"]\+\)\"\].*/\\1\t\\2/p" \
    >> "$dest"
}

build_metric_selector() {
  local extra="$1"
  local selector="$VM_NODE_SELECTOR"
  if [[ -n "$selector" && -n "$extra" ]]; then
    selector="$selector,$extra"
  elif [[ -z "$selector" && -n "$extra" ]]; then
    selector="$extra"
  fi
  if [[ -n "$selector" ]]; then
    printf "{%s}" "$selector"
  else
    printf "{}"
  fi
}

build_cluster_selector() {
  local extra="$1"
  local parts=()
  if [[ -n "$extra" ]]; then
    parts+=("$extra")
  fi
  if [[ -n "$VM_NODE_SELECTOR" ]]; then
    parts+=("$VM_NODE_SELECTOR")
  fi
  if [[ -n "$CLUSTER_INSTANCE_SELECTOR" ]]; then
    parts+=("$CLUSTER_INSTANCE_SELECTOR")
  fi
  if (( ${#parts[@]} == 0 )); then
    printf "{}"
  else
    local joined
    joined=$(IFS=,; echo "${parts[*]}")
    printf "{%s}" "$joined"
  fi
}

vm_fetch_vector_tsv() {
  local promql="$1"
  local eval_ts="$2"
  local dest="$3"
  local label="${4:-instance}"
  local json_tmp
  json_tmp=$(mktemp "$TMP_DIR/vm_vector_json.XXXXXX")
  if vm_query_instant_to_file "$promql" "$eval_ts" "$json_tmp"; then
    parse_vm_vector_response "$json_tmp" "$dest" "$label"
  else
    : >"$dest"
  fi
  rm -f "$json_tmp"
}

join_vm_metrics_to_tsv() {
  local dest="$1"
  shift
  : >"$dest"
  local metric_names=()
  local metric_files=()
  while [[ $# -gt 1 ]]; do
    metric_names+=("$1")
    metric_files+=("$2")
    shift 2
  done
  local names_csv
  names_csv=$(IFS=','; echo "${metric_names[*]}")
  awk -F'\t' -v DEST="$dest" -v NAMES="$names_csv" '
  BEGIN {
    split(NAMES, metric_names, ",")
  }
  {
    if (NF < 2) next
    node=$1
    value=$2
    metric=metric_names[ARGIND]
    data[node,metric]=value
    nodes[node]=1
  }
  END {
    PROCINFO["sorted_in"] = "@ind_str_asc"
    for (node in nodes) {
      line=node
      for (i=1; i<=length(metric_names); i++) {
        key=node SUBSEP metric_names[i]
        if (key in data) {
          line=line "\t" data[key]
        } else {
          line=line "\t"
        }
      }
      print line > DEST
    }
  }' "${metric_files[@]}"
}

extract_vm_scalar() {
  local file="$1"
  awk 'match($0, /"value":\[[^,]+,"([^"]*)"\]/, m) {print m[1]; exit}' "$file"
}

vm_fetch_single_value() {
  local promql="$1"
  local eval_ts="$2"
  local json_tmp
  local tsv_tmp
  json_tmp=$(mktemp "$TMP_DIR/vm_single_json.XXXXXX")
  tsv_tmp=$(mktemp "$TMP_DIR/vm_single_tsv.XXXXXX")
  local value=""
  if vm_query_instant_to_file "$promql" "$eval_ts" "$json_tmp"; then
    parse_vm_vector_response "$json_tmp" "$tsv_tmp"
    value=$(awk -F'\t' 'NR==1 {print $2}' "$tsv_tmp")
  fi
  rm -f "$json_tmp" "$tsv_tmp"
  printf '%s' "$value"
}

VM_STEP_SECONDS=$((VM_BUCKET_INTERVAL_MINUTES * 60))
if (( VM_STEP_SECONDS <= 0 )); then
  VM_STEP_SECONDS=3600
fi
VM_RESOURCE_BUCKET_COUNT=$((RESOURCE_HISTORY_MINUTES / VM_BUCKET_INTERVAL_MINUTES))
if (( RESOURCE_HISTORY_MINUTES % VM_BUCKET_INTERVAL_MINUTES != 0 )); then
  VM_RESOURCE_BUCKET_COUNT=$((VM_RESOURCE_BUCKET_COUNT + 1))
fi
(( VM_RESOURCE_BUCKET_COUNT <= 0 )) && VM_RESOURCE_BUCKET_COUNT=1
CURRENT_TS=$(date -u +%s)
CURRENT_BUCKET_START=$(( (CURRENT_TS / VM_STEP_SECONDS) * VM_STEP_SECONDS ))
if (( VM_RESOURCE_BUCKET_COUNT == 1 )); then
  OLDEST_BUCKET_START=$CURRENT_BUCKET_START
else
  OLDEST_BUCKET_START=$((CURRENT_BUCKET_START - (VM_RESOURCE_BUCKET_COUNT - 1) * VM_STEP_SECONDS))
fi
VM_BUCKET_WINDOW="${VM_BUCKET_INTERVAL_MINUTES}m"

# CK Pod 级别资源分时序列（来自 VM）
CK_POD_TIMESERIES_CSV="$TIMESERIES_DIR/ck_pod_usage_timeseries.csv"
echo "pod_name,start_time,end_time,cpu_usage_percent,memory_usage_bytes,net_rx_mbps,net_tx_mbps,disk_read_mbps,disk_write_mbps,cpu_throttle_percent" > "$CK_POD_TIMESERIES_CSV"
log "Collecting CK Pod metrics from VM (Namespace: $CK_K8S_NAMESPACE)"
log "Discovering pods in namespace: $CK_K8S_NAMESPACE"
DISCOVERED_PODS=$(kubectl get pods -n "$CK_K8S_NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | tr -s '[:space:]' ' ' || echo "")
if [[ -n "$DISCOVERED_PODS" ]]; then
  log "  -> Found pods: $DISCOVERED_PODS"
  read -r -a POD_ARRAY <<<"$DISCOVERED_PODS"
  for pod in "${POD_ARRAY[@]}"; do
    [[ -z "$pod" ]] && continue
    log "    - Pod: $pod"
  done
else
  log "WARNING: No pods found in namespace $CK_K8S_NAMESPACE via kubectl. Metrics might be empty."
fi
CK_POD_CPU_PROMQL=$(printf 'avg_over_time(sum by (pod) (rate(container_cpu_usage_seconds_total{namespace="%s", container!="POD", container!=""}[5m])) * 100 [%s])' "$CK_K8S_NAMESPACE" "$VM_BUCKET_WINDOW")
CK_POD_MEM_PROMQL=$(printf 'avg_over_time(sum by (pod) (container_memory_working_set_bytes{namespace="%s", container!="POD", container!=""}) [%s])' "$CK_K8S_NAMESPACE" "$VM_BUCKET_WINDOW")
CK_POD_NET_RX_PROMQL=$(printf "avg_over_time(sum by (pod) (rate(container_network_receive_bytes_total{namespace=\"%s\"}[5m])) / 1000000 [%s])" "$CK_K8S_NAMESPACE" "$VM_BUCKET_WINDOW")
CK_POD_NET_TX_PROMQL=$(printf "avg_over_time(sum by (pod) (rate(container_network_transmit_bytes_total{namespace=\"%s\"}[5m])) / 1000000 [%s])" "$CK_K8S_NAMESPACE" "$VM_BUCKET_WINDOW")
CK_POD_DISK_R_PROMQL=$(printf "avg_over_time(sum by (pod) (rate(container_fs_reads_bytes_total{namespace=\"%s\"}[5m])) / 1000000 [%s])" "$CK_K8S_NAMESPACE" "$VM_BUCKET_WINDOW")
CK_POD_DISK_W_PROMQL=$(printf "avg_over_time(sum by (pod) (rate(container_fs_writes_bytes_total{namespace=\"%s\"}[5m])) / 1000000 [%s])" "$CK_K8S_NAMESPACE" "$VM_BUCKET_WINDOW")
CK_POD_THROTTLE_PROMQL=$(printf 'avg_over_time(sum by (pod) (rate(container_cpu_cfs_throttled_seconds_total{namespace="%s", container!="POD", container!=""}[5m])) * 100 [%s])' "$CK_K8S_NAMESPACE" "$VM_BUCKET_WINDOW")
for ((bucket_index=0; bucket_index<VM_RESOURCE_BUCKET_COUNT; bucket_index++)); do
  bucket_start=$((OLDEST_BUCKET_START + bucket_index * VM_STEP_SECONDS))
  bucket_end=$((bucket_start + VM_STEP_SECONDS))
  progress_minutes=$(((bucket_index + 1) * VM_BUCKET_INTERVAL_MINUTES))
  progress_days=$(awk -v m="$progress_minutes" 'BEGIN {printf "%.2f", m/1440}')
  log_progress "Collecting CK Pod metrics: ${progress_days}/${RESOURCE_HISTORY_DAYS} days (bucket $((bucket_index+1))/$VM_RESOURCE_BUCKET_COUNT)"
  start_time_iso=$(date -u -d "@$bucket_start" +"%Y-%m-%dT%H:%M:%SZ")
  end_time_iso=$(date -u -d "@$bucket_end" +"%Y-%m-%dT%H:%M:%SZ")
  CPU_TSV=$(mktemp "$TMP_DIR/ck_pod_cpu.XXXXXX")
  MEM_TSV=$(mktemp "$TMP_DIR/ck_pod_mem.XXXXXX")
  NET_RX_TSV=$(mktemp "$TMP_DIR/ck_pod_rx.XXXXXX")
  NET_TX_TSV=$(mktemp "$TMP_DIR/ck_pod_tx.XXXXXX")
  DISK_R_TSV=$(mktemp "$TMP_DIR/ck_pod_dr.XXXXXX")
  DISK_W_TSV=$(mktemp "$TMP_DIR/ck_pod_dw.XXXXXX")
  THROTTLE_TSV=$(mktemp "$TMP_DIR/ck_pod_thr.XXXXXX")
  vm_fetch_vector_tsv "$CK_POD_CPU_PROMQL" "$bucket_end" "$CPU_TSV" "pod"
  vm_fetch_vector_tsv "$CK_POD_MEM_PROMQL" "$bucket_end" "$MEM_TSV" "pod"
  vm_fetch_vector_tsv "$CK_POD_NET_RX_PROMQL" "$bucket_end" "$NET_RX_TSV" "pod"
  vm_fetch_vector_tsv "$CK_POD_NET_TX_PROMQL" "$bucket_end" "$NET_TX_TSV" "pod"
  vm_fetch_vector_tsv "$CK_POD_DISK_R_PROMQL" "$bucket_end" "$DISK_R_TSV" "pod"
  vm_fetch_vector_tsv "$CK_POD_DISK_W_PROMQL" "$bucket_end" "$DISK_W_TSV" "pod"
  vm_fetch_vector_tsv "$CK_POD_THROTTLE_PROMQL" "$bucket_end" "$THROTTLE_TSV" "pod"
  JOINED_TSV=$(mktemp "$TMP_DIR/ck_pod_joined.XXXXXX")
  join_vm_metrics_to_tsv "$JOINED_TSV" \
    "cpu" "$CPU_TSV" \
    "mem" "$MEM_TSV" \
    "rx" "$NET_RX_TSV" \
    "tx" "$NET_TX_TSV" \
    "dr" "$DISK_R_TSV" \
    "dw" "$DISK_W_TSV" \
    "thr" "$THROTTLE_TSV"
  while IFS=$'\t' read -r pod_name cpu_val mem_val rx_val tx_val dr_val dw_val thr_val; do
    [[ -z "$pod_name" ]] && continue
    echo "${pod_name},${start_time_iso},${end_time_iso},${cpu_val:-},${mem_val:-},${rx_val:-},${tx_val:-},${dr_val:-},${dw_val:-},${thr_val:-}" >> "$CK_POD_TIMESERIES_CSV"
  done <"$JOINED_TSV"
  rm -f "$CPU_TSV" "$MEM_TSV" "$NET_RX_TSV" "$NET_TX_TSV" "$DISK_R_TSV" "$DISK_W_TSV" "$THROTTLE_TSV" "$JOINED_TSV"
done
>&2 echo ""

# 集群所有节点资源分时序列（来自 VM）
NODE_CLUSTER_TIMESERIES_CSV="$TIMESERIES_DIR/cluster_node_usage_timeseries.csv"
echo "node_name,start_time,end_time,cpu_usage_percent,memory_usage_percent,disk_usage_percent,load_1,load_5,load_15,swap_usage_percent,disk_read_mbps,disk_write_mbps,net_rx_mbps,net_tx_mbps" > "$NODE_CLUSTER_TIMESERIES_CSV"
CLUSTER_INSTANCE_SELECTOR=""
CLUSTER_TARGET_LABEL=""
if [[ -n "$VM_NODE_SELECTOR" ]]; then
  log "Using provided VM node selector: $VM_NODE_SELECTOR"
  CLUSTER_TARGET_LABEL="$VM_NODE_SELECTOR"
elif [[ -n "$AUTO_CLUSTER_IP_REGEX" ]]; then
  log "Using auto-discovered IPs for cluster query"
  CLUSTER_INSTANCE_SELECTOR=$(printf 'instance=~"%s"' "$AUTO_CLUSTER_IP_REGEX")
  CLUSTER_TARGET_LABEL="$AUTO_CLUSTER_IP_REGEX"
fi
if [[ -n "$VM_NODE_SELECTOR" || -n "$CLUSTER_INSTANCE_SELECTOR" ]]; then
  log "Collecting cluster node timeseries from VictoriaMetrics"
  CLUSTER_CPU_SELECTOR=$(build_cluster_selector 'mode!="idle"')
  CLUSTER_MEM_SELECTOR=$(build_cluster_selector "")
  CLUSTER_DISK_SELECTOR=$(build_cluster_selector 'fstype!~"tmpfs|overlay"')
  CLUSTER_LOAD_SELECTOR=$(build_cluster_selector "")
  CLUSTER_DISK_IO_SELECTOR=$(build_cluster_selector 'device!~"loop.*|ram.*"')
  CLUSTER_NET_SELECTOR=$(build_cluster_selector 'device!="lo"')
  CLUSTER_CPU_PROMQL=$(printf "avg_over_time(sum by (instance) (rate(node_cpu_seconds_total%s[5m])) * 100 [%s])" "$CLUSTER_CPU_SELECTOR" "$VM_BUCKET_WINDOW")
  CLUSTER_MEM_PROMQL=$(printf "avg_over_time((1 - (node_memory_MemAvailable_bytes%s / node_memory_MemTotal_bytes%s)) * 100 [%s])" "$CLUSTER_MEM_SELECTOR" "$CLUSTER_MEM_SELECTOR" "$VM_BUCKET_WINDOW")
  CLUSTER_DISK_PROMQL=$(printf "avg_over_time((1 - (node_filesystem_avail_bytes%s / node_filesystem_size_bytes%s)) * 100 [%s])" "$CLUSTER_DISK_SELECTOR" "$CLUSTER_DISK_SELECTOR" "$VM_BUCKET_WINDOW")
  CLUSTER_LOAD1_PROMQL=$(printf "avg_over_time(node_load1%s[%s])" "$CLUSTER_LOAD_SELECTOR" "$VM_BUCKET_WINDOW")
  CLUSTER_LOAD5_PROMQL=$(printf "avg_over_time(node_load5%s[%s])" "$CLUSTER_LOAD_SELECTOR" "$VM_BUCKET_WINDOW")
  CLUSTER_LOAD15_PROMQL=$(printf "avg_over_time(node_load15%s[%s])" "$CLUSTER_LOAD_SELECTOR" "$VM_BUCKET_WINDOW")
  CLUSTER_SWAP_PROMQL=$(printf "avg_over_time((1 - (node_memory_SwapFree_bytes%s / clamp_min(node_memory_SwapTotal_bytes%s,1))) * 100 [%s])" "$CLUSTER_MEM_SELECTOR" "$CLUSTER_MEM_SELECTOR" "$VM_BUCKET_WINDOW")
  CLUSTER_DISK_READ_PROMQL=$(printf "avg_over_time((sum by (instance) (rate(node_disk_read_bytes_total%s[5m])) / 1000000) [%s])" "$CLUSTER_DISK_IO_SELECTOR" "$VM_BUCKET_WINDOW")
  CLUSTER_DISK_WRITE_PROMQL=$(printf "avg_over_time((sum by (instance) (rate(node_disk_written_bytes_total%s[5m])) / 1000000) [%s])" "$CLUSTER_DISK_IO_SELECTOR" "$VM_BUCKET_WINDOW")
  CLUSTER_NET_RX_PROMQL=$(printf "avg_over_time((sum by (instance) (rate(node_network_receive_bytes_total%s[5m])) / 1000000) [%s])" "$CLUSTER_NET_SELECTOR" "$VM_BUCKET_WINDOW")
  CLUSTER_NET_TX_PROMQL=$(printf "avg_over_time((sum by (instance) (rate(node_network_transmit_bytes_total%s[5m])) / 1000000) [%s])" "$CLUSTER_NET_SELECTOR" "$VM_BUCKET_WINDOW")
  for ((bucket_index=0; bucket_index<VM_RESOURCE_BUCKET_COUNT; bucket_index++)); do
    bucket_start=$((OLDEST_BUCKET_START + bucket_index * VM_STEP_SECONDS))
    bucket_end=$((bucket_start + VM_STEP_SECONDS))
    progress_minutes=$(((bucket_index + 1) * VM_BUCKET_INTERVAL_MINUTES))
    progress_days=$(awk -v m="$progress_minutes" 'BEGIN {printf "%.2f", m/1440}')
    log_progress "Collecting cluster node metrics (${CLUSTER_TARGET_LABEL:-auto-selector}): ${progress_days}/${RESOURCE_HISTORY_DAYS} days (hour bucket $((bucket_index+1))/$VM_RESOURCE_BUCKET_COUNT)"
    start_time_iso=$(date -u -d "@$bucket_start" +"%Y-%m-%dT%H:%M:%SZ")
    end_time_iso=$(date -u -d "@$bucket_end" +"%Y-%m-%dT%H:%M:%SZ")
    CPU_TSV=$(mktemp "$TMP_DIR/vm_cpu_tsv.XXXXXX")
    MEM_TSV=$(mktemp "$TMP_DIR/vm_mem_tsv.XXXXXX")
    DISK_TSV=$(mktemp "$TMP_DIR/vm_disk_tsv.XXXXXX")
    LOAD1_TSV=$(mktemp "$TMP_DIR/vm_load1_tsv.XXXXXX")
    LOAD5_TSV=$(mktemp "$TMP_DIR/vm_load5_tsv.XXXXXX")
    LOAD15_TSV=$(mktemp "$TMP_DIR/vm_load15_tsv.XXXXXX")
    SWAP_TSV=$(mktemp "$TMP_DIR/vm_swap_tsv.XXXXXX")
    DISK_READ_TSV=$(mktemp "$TMP_DIR/vm_disk_read_tsv.XXXXXX")
    DISK_WRITE_TSV=$(mktemp "$TMP_DIR/vm_disk_write_tsv.XXXXXX")
    NET_RX_TSV=$(mktemp "$TMP_DIR/vm_net_rx_tsv.XXXXXX")
    NET_TX_TSV=$(mktemp "$TMP_DIR/vm_net_tx_tsv.XXXXXX")
    vm_fetch_vector_tsv "$CLUSTER_CPU_PROMQL" "$bucket_end" "$CPU_TSV" "instance"
    vm_fetch_vector_tsv "$CLUSTER_MEM_PROMQL" "$bucket_end" "$MEM_TSV" "instance"
    vm_fetch_vector_tsv "$CLUSTER_DISK_PROMQL" "$bucket_end" "$DISK_TSV" "instance"
    vm_fetch_vector_tsv "$CLUSTER_LOAD1_PROMQL" "$bucket_end" "$LOAD1_TSV" "instance"
    vm_fetch_vector_tsv "$CLUSTER_LOAD5_PROMQL" "$bucket_end" "$LOAD5_TSV" "instance"
    vm_fetch_vector_tsv "$CLUSTER_LOAD15_PROMQL" "$bucket_end" "$LOAD15_TSV" "instance"
    vm_fetch_vector_tsv "$CLUSTER_SWAP_PROMQL" "$bucket_end" "$SWAP_TSV" "instance"
    vm_fetch_vector_tsv "$CLUSTER_DISK_READ_PROMQL" "$bucket_end" "$DISK_READ_TSV" "instance"
    vm_fetch_vector_tsv "$CLUSTER_DISK_WRITE_PROMQL" "$bucket_end" "$DISK_WRITE_TSV" "instance"
    vm_fetch_vector_tsv "$CLUSTER_NET_RX_PROMQL" "$bucket_end" "$NET_RX_TSV" "instance"
    vm_fetch_vector_tsv "$CLUSTER_NET_TX_PROMQL" "$bucket_end" "$NET_TX_TSV" "instance"
    JOINED_TSV=$(mktemp "$TMP_DIR/vm_joined_tsv.XXXXXX")
    # 多指标结果分别存储，这里通过 join_vm_metrics_to_tsv 统一按节点合并，避免遗漏
    join_vm_metrics_to_tsv "$JOINED_TSV" \
      "cpu" "$CPU_TSV" \
      "mem" "$MEM_TSV" \
      "disk" "$DISK_TSV" \
      "load1" "$LOAD1_TSV" \
      "load5" "$LOAD5_TSV" \
      "load15" "$LOAD15_TSV" \
      "swap" "$SWAP_TSV" \
      "disk_read" "$DISK_READ_TSV" \
      "disk_write" "$DISK_WRITE_TSV" \
      "net_rx" "$NET_RX_TSV" \
      "net_tx" "$NET_TX_TSV"
    while IFS=$'\t' read -r node_name cpu_val mem_val disk_val load1_val load5_val load15_val swap_val disk_read_val disk_write_val net_rx_val net_tx_val; do
      [[ -z "$node_name" ]] && continue
      clean_node_name="${node_name%%:*}"
      echo "${clean_node_name},${start_time_iso},${end_time_iso},${cpu_val:-},${mem_val:-},${disk_val:-},${load1_val:-},${load5_val:-},${load15_val:-},${swap_val:-},${disk_read_val:-},${disk_write_val:-},${net_rx_val:-},${net_tx_val:-}" >> "$NODE_CLUSTER_TIMESERIES_CSV"
    done <"$JOINED_TSV"
    rm -f "$CPU_TSV" "$MEM_TSV" "$DISK_TSV" "$LOAD1_TSV" "$LOAD5_TSV" "$LOAD15_TSV" "$SWAP_TSV" "$DISK_READ_TSV" "$DISK_WRITE_TSV" "$NET_RX_TSV" "$NET_TX_TSV" "$JOINED_TSV"
  done
  >&2 echo ""
else
  log "WARNING: No VM node selector provided AND failed to discover node IPs. Skipping cluster node usage timeseries"
fi

# 汇总最终 JSON 输出
CLUSTER_OVERVIEW_JSON=$(cat <<EOF
{
  "ck_version": $(json_string "$CK_VERSION_VALUE"),
  "cluster_node_count": $(json_number_or_null "$CLUSTER_NODE_COUNT"),
  "chi_shards_count": $(json_number_or_null "$CHI_SHARDS"),
  "chi_replicas_count": $(json_number_or_null "$CHI_REPLICAS"),
  "chi_expected_node_count": $(json_number_or_null "$CHI_EXPECTED_NODE_COUNT")
}
EOF
)

TABLES_JSON=$(cat <<EOF
{
  "all_tables_stats_csv": $(json_string "$TABLE_STATS_CSV"),
  "all_tables_schema_csv": $(json_string "$TABLE_SCHEMA_CSV"),
  "business_ttl_csv": $(json_string "$BUSINESS_TTL_CSV"),
  "business_table_writes_dir": $(json_string "$BUSINESS_WRITES_DIR")
}
EOF
)

SCHEMAS_JSON=$(cat <<EOF
{
  "all_tables_schema_csv": $(json_string "$TABLE_SCHEMA_CSV")
}
EOF
)

TRAFFIC_JSON=$(cat <<EOF
{
  "business_table_writes_dir": $(json_string "$BUSINESS_WRITES_DIR"),
  "business_query_log_stats": {
    "writes_dir": $(json_string "$BUSINESS_QUERY_LOG_WRITES_DIR"),
    "reads_dir": $(json_string "$BUSINESS_QUERY_LOG_READS_DIR")
  },
  "query_log_written_bytes_timeseries_csv": $(json_string "$QUERY_LOG_WRITTEN_BYTES_CSV"),
  "slow_queries_csv": $(json_string "$SLOW_QUERIES_CSV")
}
EOF
)

NODE_LEVEL_JSON=$(cat <<EOF
{
  "hostname": $(json_string "$HOSTNAME"),
  "server_model": $(json_string "$SERVER_MODEL"),
  "os_arch": $(json_string "$OS_ARCH"),
  "os_kernel": $(json_string "$OS_KERNEL"),
  "cpu_cores": $(json_number_or_null "$CPU_CORES"),
  "memory_total_bytes": $(json_number_or_null "$MEM_TOTAL"),
  "memory_used_bytes": $(json_number_or_null "$MEM_USED"),
  "disk_total_bytes": $(json_number_or_null "$DISK_TOTAL"),
  "disk_used_bytes": $(json_number_or_null "$DISK_USED"),
  "memory_usage_percent": $(json_number_or_null "$MEM_USAGE_PERCENT"),
  "disk_usage_percent": $(json_number_or_null "$DISK_USAGE_PERCENT"),
  "load_avg_1min": $(json_number_or_null "$LOAD_1"),
  "load_avg_5min": $(json_number_or_null "$LOAD_5"),
  "load_avg_15min": $(json_number_or_null "$LOAD_15"),
  "cpu_flags": $(json_string "$CPU_FLAGS"),
  "swap_total_bytes": $(json_number_or_null "$SWAP_TOTAL"),
  "swap_used_bytes": $(json_number_or_null "$SWAP_USED"),
  "fd_allocated": $(json_number_or_null "$FD_ALLOC"),
  "fd_max": $(json_number_or_null "$FD_MAX"),
  "tcp_in_use": $(json_number_or_null "$TCP_IN_USE"),
  "tcp_time_wait": $(json_number_or_null "$TCP_TIME_WAIT"),
  "storage_volumes_csv": $(json_string "$STORAGE_VOLUMES_CSV"),
  "disk_usage_details_csv": $(json_string "$DISK_USAGE_CSV"),
  "k8s_nodes_csv": $(json_string "$K8S_NODES_CSV"),
  "cluster_nodes_timeseries_csv": $(json_string "$NODE_CLUSTER_TIMESERIES_CSV")
}
EOF
)

CK_LEVEL_JSON=$(cat <<EOF
{
  "pod_usage_timeseries_csv": $(json_string "$CK_POD_TIMESERIES_CSV")
}
EOF
)
COLLECTION_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

META_JSON=$(cat <<EOF
{
  "collection_timestamp": $(json_string "$COLLECTION_TIMESTAMP"),
  "helm_values_dir": $(json_string "$HELM_OUTPUT_DIR"),
  "system_settings_csv": $(json_string "$SYSTEM_SETTINGS_CSV"),
  "system_build_options_csv": $(json_string "$SYSTEM_BUILD_OPTIONS_CSV")
}
EOF
)

log "Assembling final summary JSON"
FINAL_JSON=$(cat <<EOF
{
  "cluster_overview": $CLUSTER_OVERVIEW_JSON,
  "tables": $TABLES_JSON,
  "schemas": $SCHEMAS_JSON,
  "traffic": $TRAFFIC_JSON,
  "resources": {
    "node_level": $NODE_LEVEL_JSON,
    "ck_level": $CK_LEVEL_JSON
  },
  "meta": $META_JSON
}
EOF
)

OUTPUT_FILE="$OUTPUT_DIR/migration_metrics.json"
printf '%s\n' "$FINAL_JSON" >"$OUTPUT_FILE"
log "Collection finished. JSON summary saved to $OUTPUT_FILE"

if [[ "$COMPRESS_OUTPUT" == "true" ]]; then
  ARCHIVE_NAME="${OUTPUT_DIR}.tar.gz"
  log "Compressing output directory to $ARCHIVE_NAME"
  if tar -czf "$ARCHIVE_NAME" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")"; then
    log "Compression successful. Removing original directory: $OUTPUT_DIR"
    rm -rf "$OUTPUT_DIR"
    log "Final output saved to: $ARCHIVE_NAME"
  else
    log "ERROR: Compression failed. Original directory preserved at: $OUTPUT_DIR"
  fi
fi
