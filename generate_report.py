#!/usr/bin/env python3
import csv
import re
import sys
from pathlib import Path
from datetime import datetime, timedelta
from xml.sax.saxutils import escape

input_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./migration_report")
pdf_path = input_dir / "report.pdf"
pdf_path.parent.mkdir(parents=True, exist_ok=True)

def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def get_value(row, key, default=""):
    return row.get(key, default)

def to_gb(value):
    try:
        return "{:.2f}".format(float(value) / (1024 ** 3))
    except Exception:
        return "0.00"

def format_plain_number(value):
    try:
        val = float(value)
    except Exception:
        return ""
    text = "{:.2f}".format(val)
    text = text.rstrip("0").rstrip(".")
    return text

def parse_cpu_to_cores(value):
    try:
        val = str(value).strip()
        if not val:
            return ""
        if val.endswith("m"):
            return format_plain_number(float(val[:-1]) / 1000.0)
        return format_plain_number(float(val))
    except Exception:
        return ""

def to_gb_from_mem(value):
    try:
        val = str(value).strip()
        if not val:
            return ""
        if val.endswith("Ki"):
            val = float(val[:-2]) / (1024 ** 2)
        elif val.endswith("Mi"):
            val = float(val[:-2]) / 1024.0
        elif val.endswith("Gi"):
            val = float(val[:-2])
        elif val.endswith("Ti"):
            val = float(val[:-2]) * 1024.0
        else:
            val = float(val) / (1024 ** 3)
        return "{:.2f}".format(val)
    except Exception:
        return ""

def to_gb_from_kib(value):
    try:
        val = str(value).strip()
        if val.endswith("Ki"):
            val = val[:-2]
        return "{:.2f}".format(float(val) / (1024 ** 2))
    except Exception:
        return "0.00"

metrics_text = (input_dir / "migration_metrics.json").read_text(encoding="utf-8")
match = re.search(r'"cpu_flags"\s*:\s*"([^"]*)"', metrics_text)
cpu_flags = match.group(1) if match else ""
avx2_supported = "支持AVX2" if "avx2" in cpu_flags else "不支持AVX2"
cpu_value = "{}（{}）".format(cpu_flags, avx2_supported) if cpu_flags else avx2_supported

k8s_nodes = read_csv(input_dir / "snapshots/cluster_k8s_nodes.csv")
device_mapper_rows = []
device_mapper_path = input_dir / "snapshots/device_mapper.csv"
if device_mapper_path.exists():
    device_mapper_rows = read_csv(device_mapper_path)
device_mapper = {}
for r in device_mapper_rows:
    mapper_name = (r.get("mapper_name") or "").strip()
    device_name = (r.get("device") or "").strip()
    if mapper_name and device_name:
        device_mapper[mapper_name] = device_name
node_rows = [
    [
        get_value(r, "name"),
        get_value(r, "internal_ip"),
        get_value(r, "os_image"),
        get_value(r, "kernel_version"),
        get_value(r, "cpu_capacity"),
        to_gb_from_kib(get_value(r, "memory_capacity")),
        get_value(r, "cpu_allocatable"),
        to_gb_from_kib(get_value(r, "memory_allocatable")),
        parse_cpu_to_cores(get_value(r, "cpu_requests")),
        parse_cpu_to_cores(get_value(r, "cpu_limits")),
        to_gb_from_mem(get_value(r, "memory_requests")),
        to_gb_from_mem(get_value(r, "memory_limits")),
        get_value(r, "creation_timestamp"),
    ]
    for r in k8s_nodes
]

volumes = read_csv(input_dir / "snapshots/cluster_storage_volumes.csv")
volume_rows = [
    [
        r["node_host"],
        r["name"],
        r["path"],
        to_gb(r["total_space_bytes"]),
        to_gb(r["free_space_bytes"]),
        to_gb(r["keep_free_space_bytes"]),
    ]
    for r in volumes
]

business_ttl = read_csv(input_dir / "business_ttl.csv")
ttl_rows = [
    [r["database"], r["table"], r["ttl_expression"], r["ttl_value"]]
    for r in business_ttl
    if r["ttl_value"] != "180"
]

table_stats = read_csv(input_dir / "table_stats.csv")
business_rows_all = [r for r in table_stats if r["database"] == "business"]
business_rows = [r for r in business_rows_all if r.get("engine") != "Distributed"]
business_zero = sum(1 for r in business_rows if int(float(r["total_rows"])) == 0)
business_nonzero = sum(1 for r in business_rows if int(float(r["total_rows"])) > 0)

top10 = sorted(
    business_rows_all,
    key=lambda r: float(r["uncompressed_size_bytes"]),
    reverse=True,
)[:10]
top10_rows = [
    [
        r["database"],
        r["table"],
        r["engine"],
        r["total_rows"],
        to_gb(r["compressed_size_bytes"]),
        to_gb(r["uncompressed_size_bytes"]),
    ]
    for r in top10
]

time_range = read_csv(input_dir / "timeseries/query_time_range_distribution_by_user_group.csv")
non_human = [r for r in time_range if r["user_group"] == "__NON_HUMAN__"]
non_human_sorted = sorted(non_human, key=lambda r: float(r.get("p100_days") or 0), reverse=True)[:10]
time_rows = [
    [
        r.get("table_name", r.get("table", "")),
        r.get("p50_days", ""),
        r.get("p80_days", ""),
        r.get("p90_days", ""),
        r.get("p95_days", ""),
        r.get("p99_days", ""),
        r.get("p100_days", ""),
    ]
    for r in non_human_sorted
]

non_business = [[r["database"], r["table"]] for r in table_stats if r["database"] != "business"]
views = read_csv(input_dir / "views_ddl.csv")
views_rows = [[r["database"], r["view"], r["engine"], r["create_table_query_one_line"]] for r in views]

plot_mode = "matplotlib"
plt = None
font_prop = None
try:
    import matplotlib
    import matplotlib.pyplot as plt
    import matplotlib.font_manager as font_manager
    available_fonts = {f.name for f in font_manager.fontManager.ttflist}
    preferred_fonts = ["PingFang SC", "Heiti SC", "STHeiti", "Arial Unicode MS", "SimHei", "DejaVu Sans"]
    selected_fonts = [f for f in preferred_fonts if f in available_fonts]
    if not selected_fonts:
        selected_fonts = ["DejaVu Sans"]
    matplotlib.rcParams["font.sans-serif"] = selected_fonts
    matplotlib.rcParams["axes.unicode_minus"] = False
    font_prop = font_manager.FontProperties(family=selected_fonts)
except Exception as e:
    sys.stderr.write("ERROR: 绘图依赖未就绪，请安装 matplotlib。\n")
    sys.stderr.write("ERROR: {}\n".format(e))
    sys.exit(1)

def parse_prom_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = re.match(r'^([^{\s]+)(\{[^}]+\})?\s+([^\s]+)(?:\s+([^\s]+))?$', line)
    if not m:
        return None
    metric = m.group(1)
    labels_raw = m.group(2) or ""
    value_str = m.group(3)
    ts_str = m.group(4)
    try:
        value = float(value_str)
    except Exception:
        return None
    ts = None
    if ts_str:
        try:
            ts = int(ts_str)
        except Exception:
            ts = None
    labels = {}
    if labels_raw.startswith("{") and labels_raw.endswith("}"):
        body = labels_raw[1:-1]
        parts = re.findall(r'(\w+)=(".*?"|[^,]+)', body)
        for k, v in parts:
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            labels[k] = v
    return metric, labels, value, ts

def ensure_dir(p):
    Path(p).mkdir(parents=True, exist_ok=True)

def label_repr(labels):
    if "instance" in labels and "device" in labels:
        return "instance={} device={}".format(labels["instance"], labels["device"])
    if "pod" in labels and "device" in labels:
        return "pod={} device={}".format(labels["pod"], labels["device"])
    for key in ("instance", "pod", "host", "device", "table", "name"):
        if key in labels:
            return "{}={}".format(key, labels[key])
    items = ["{}={}".format(k, labels[k]) for k in sorted(labels.keys())]
    return ",".join(items) if items else "all"

def format_number(value):
    try:
        return "{:.2f}".format(float(value))
    except Exception:
        return ""

def series_avg(points):
    if not points:
        return ""
    return format_number(sum(p[1] for p in points) / float(len(points)))

def series_max(points):
    if not points:
        return ""
    return format_number(max(p[1] for p in points))

def format_avg_max(avg_points, max_points):
    avg_value = series_avg(avg_points)
    max_value = series_max(max_points)
    if avg_value == "" and max_value == "":
        return ""
    if avg_value == "":
        return max_value
    if max_value == "":
        return avg_value
    return "{} / {}".format(avg_value, max_value)

def series_latest(points):
    if not points:
        return None
    return points[-1][1]

def get_series_points(metrics, metric_name, instance, device=None):
    series_map = metrics.get(metric_name, {})
    if instance:
        if device:
            key = "instance={} device={}".format(instance, device)
            if key in series_map:
                return series_map[key]
            return []
        key = "instance={}".format(instance)
        if key in series_map:
            return series_map[key]
    return []

def parse_instance_device(series_key):
    instance = None
    device = None
    for part in series_key.split(" "):
        if part.startswith("instance="):
            instance = part[len("instance="):]
        elif part.startswith("device="):
            device = part[len("device="):]
    return instance, device

def category_for_file(fname):
    if fname == "cluster_node_usage_timeseries.prom":
        return "节点资源使用"
    if fname == "cluster_filesystem_usage_timeseries.prom":
        return "节点文件系统"
    if fname == "ck_pod_usage_timeseries.prom":
        return "CK Pod资源"
    if fname == "clickhouse_metrics_timeseries.prom":
        return "ClickHouse关键指标"
    if fname == "business_table_writes_timeseries.prom":
        return "业务表写入"
    return "其它时序"


def metric_desc(mname, y_label):
    desc_map = {
        "sr_migration_business_table_written_rows": "说明：业务表写入行数（按logType聚合），反映各业务日志类型的写入量变化。",
        "sr_migration_ck_pod_cpu_usage_percent_avg": "说明：CK Pod CPU使用率平均值，用于观察Pod计算负载。",
        "sr_migration_ck_pod_cpu_usage_percent_max": "说明：CK Pod CPU使用率峰值，用于识别Pod CPU尖峰。",
        "sr_migration_ck_pod_cpu_throttle_percent_avg": "说明：CK Pod CPU节流占比平均值，反映CPU限额造成的节流程度。",
        "sr_migration_ck_pod_cpu_throttle_percent_max": "说明：CK Pod CPU节流占比峰值，用于识别突发节流。",
        "sr_migration_ck_pod_memory_usage_bytes_avg": "说明：CK Pod内存Working Set平均值（{}），用于观察实际活跃内存占用。".format(y_label.replace("值", "")),
        "sr_migration_ck_pod_memory_usage_bytes_max": "说明：CK Pod内存Working Set峰值（{}），用于识别内存尖峰。".format(y_label.replace("值", "")),
        "sr_migration_ck_pod_memory_usage_bytes_total_avg": "说明：CK Pod内存使用量平均值（{}，包含缓存），用于评估内存压力。".format(y_label.replace("值", "")),
        "sr_migration_ck_pod_memory_usage_bytes_total_max": "说明：CK Pod内存使用量峰值（{}，包含缓存），用于识别内存峰值。".format(y_label.replace("值", "")),
        "sr_migration_ck_pod_net_rx_mbps_avg": "说明：CK Pod网络接收速率平均值（MB/s），反映入站带宽使用。",
        "sr_migration_ck_pod_net_rx_mbps_max": "说明：CK Pod网络接收速率峰值（MB/s），用于识别入站突发流量。",
        "sr_migration_ck_pod_net_tx_mbps_avg": "说明：CK Pod网络发送速率平均值（MB/s），反映出站带宽使用。",
        "sr_migration_ck_pod_net_tx_mbps_max": "说明：CK Pod网络发送速率峰值（MB/s），用于识别出站突发流量。",
        "sr_migration_clickhouse_metrics_merges_avg": "说明：ClickHouse后台合并任务数平均值，用于观察合并压力。",
        "sr_migration_clickhouse_metrics_merges_max": "说明：ClickHouse后台合并任务数峰值，用于识别合并高峰。",
        "sr_migration_clickhouse_metrics_parts_active_avg": "说明：活跃Part数量平均值，用于评估存储碎片情况。",
        "sr_migration_clickhouse_metrics_parts_active_max": "说明：活跃Part数量峰值，用于识别Part累积。",
        "sr_migration_clickhouse_metrics_queries_avg": "说明：正在执行查询数平均值，反映查询并发水平。",
        "sr_migration_clickhouse_metrics_queries_max": "说明：正在执行查询数峰值，用于识别并发高峰。",
        "sr_migration_clickhouse_metrics_global_threads_active_avg": "说明：活跃线程数平均值，反映整体执行负载。",
        "sr_migration_clickhouse_metrics_global_threads_active_max": "说明：活跃线程数峰值，用于识别线程高峰。",
        "sr_migration_clickhouse_metrics_memory_tracking_avg": "说明：ClickHouse内存跟踪值平均（{}），用于评估进程内存占用。".format(y_label.replace("值", "")),
        "sr_migration_clickhouse_metrics_memory_tracking_max": "说明：ClickHouse内存跟踪值峰值（{}），用于识别内存尖峰。".format(y_label.replace("值", "")),
        "sr_migration_clickhouse_metrics_tcp_connections_avg": "说明：TCP连接数平均值，反映客户端连接规模。",
        "sr_migration_clickhouse_metrics_tcp_connections_max": "说明：TCP连接数峰值，用于识别连接突增。",
        "sr_migration_clickhouse_metrics_http_connections_avg": "说明：HTTP连接数平均值，反映HTTP接口使用情况。",
        "sr_migration_clickhouse_metrics_http_connections_max": "说明：HTTP连接数峰值，用于识别HTTP连接高峰。",
        "sr_migration_clickhouse_metrics_mysql_connections_avg": "说明：MySQL协议连接数平均值，反映MySQL接口使用情况。",
        "sr_migration_clickhouse_metrics_mysql_connections_max": "说明：MySQL协议连接数峰值，用于识别连接突增。",
        "sr_migration_clickhouse_metrics_postgresql_connections_avg": "说明：PostgreSQL协议连接数平均值，反映PG接口使用情况。",
        "sr_migration_clickhouse_metrics_postgresql_connections_max": "说明：PostgreSQL协议连接数峰值，用于识别连接突增。",
        "sr_migration_clickhouse_metrics_interserver_connections_avg": "说明：Interserver连接数平均值，反映副本间通信压力。",
        "sr_migration_clickhouse_metrics_interserver_connections_max": "说明：Interserver连接数峰值，用于识别复制通信高峰。",
        "sr_migration_cluster_node_cpu_usage_percent_avg": "说明：节点CPU使用率平均值（非idle），用于观察CPU负载趋势。",
        "sr_migration_cluster_node_cpu_usage_percent_max": "说明：节点CPU使用率峰值（非idle），用于识别CPU尖峰。",
        "sr_migration_cluster_node_memory_usage_percent_avg": "说明：节点内存使用率平均值，反映内存压力水平。",
        "sr_migration_cluster_node_memory_usage_percent_max": "说明：节点内存使用率峰值，用于识别内存峰值。",
        "sr_migration_cluster_node_disk_usage_percent_avg": "说明：节点磁盘使用率平均值，反映磁盘容量占用。",
        "sr_migration_cluster_node_disk_usage_percent_max": "说明：节点磁盘使用率峰值，用于识别容量紧张节点。",
        "sr_migration_cluster_node_load1_avg": "说明：节点1分钟平均负载，反映短期负载变化。",
        "sr_migration_cluster_node_load1_max": "说明：节点1分钟负载峰值，用于识别短期突发负载。",
        "sr_migration_cluster_node_load5_avg": "说明：节点5分钟平均负载，反映中期负载水平。",
        "sr_migration_cluster_node_load5_max": "说明：节点5分钟负载峰值，用于识别持续负载高点。",
        "sr_migration_cluster_node_load15_avg": "说明：节点15分钟平均负载，反映长期负载水平。",
        "sr_migration_cluster_node_load15_max": "说明：节点15分钟负载峰值，用于识别长期高负载节点。",
        "sr_migration_cluster_node_disk_read_mbps_avg": "说明：节点按device统计的磁盘读吞吐平均值（MB/s），反映读IO压力。",
        "sr_migration_cluster_node_disk_read_mbps_max": "说明：节点按device统计的磁盘读吞吐峰值（MB/s），用于识别读突发。",
        "sr_migration_cluster_node_disk_write_mbps_avg": "说明：节点按device统计的磁盘写吞吐平均值（MB/s），反映写IO压力。",
        "sr_migration_cluster_node_disk_write_mbps_max": "说明：节点按device统计的磁盘写吞吐峰值（MB/s），用于识别写突发。",
        "sr_migration_cluster_node_disk_io_util_percent_avg": "说明：节点按device统计的磁盘IO利用率平均值（%），反映磁盘忙碌程度。",
        "sr_migration_cluster_node_disk_io_util_percent_max": "说明：节点按device统计的磁盘IO利用率峰值（%），用于识别IO高峰。",
        "sr_migration_cluster_node_disk_read_await_ms_avg": "说明：节点按device统计的磁盘读IO等待时延平均值（ms），用于分析读延迟。",
        "sr_migration_cluster_node_disk_read_await_ms_max": "说明：节点按device统计的磁盘读IO等待时延峰值（ms），用于识别读抖动。",
        "sr_migration_cluster_node_disk_write_await_ms_avg": "说明：节点按device统计的磁盘写IO等待时延平均值（ms），用于分析写延迟。",
        "sr_migration_cluster_node_disk_write_await_ms_max": "说明：节点按device统计的磁盘写IO等待时延峰值（ms），用于识别写抖动。",
        "sr_migration_cluster_node_disk_read_iops_avg": "说明：节点按device统计的磁盘读IOPS平均值，用于观察读请求压力。",
        "sr_migration_cluster_node_disk_read_iops_max": "说明：节点按device统计的磁盘读IOPS峰值，用于识别读突发。",
        "sr_migration_cluster_node_disk_write_iops_avg": "说明：节点按device统计的磁盘写IOPS平均值，用于观察写请求压力。",
        "sr_migration_cluster_node_disk_write_iops_max": "说明：节点按device统计的磁盘写IOPS峰值，用于识别写突发。",
        "sr_migration_cluster_node_net_rx_mbps_avg": "说明：节点网络接收速率平均值（MB/s），反映入站带宽使用。",
        "sr_migration_cluster_node_net_rx_mbps_max": "说明：节点网络接收速率峰值（MB/s），用于识别入站突发流量。",
        "sr_migration_cluster_node_net_tx_mbps_avg": "说明：节点网络发送速率平均值（MB/s），反映出站带宽使用。",
        "sr_migration_cluster_node_net_tx_mbps_max": "说明：节点网络发送速率峰值（MB/s），用于识别出站突发流量。",
        "sr_migration_cluster_filesystem_total_bytes": "说明：文件系统总容量（GB），用于核对磁盘规模与规划。",
        "sr_migration_cluster_filesystem_free_bytes": "说明：文件系统可用容量（GB），用于评估剩余空间。",
        "sr_migration_cluster_filesystem_used_bytes": "说明：文件系统已用容量（GB），用于观察容量增长趋势。",
        "sr_migration_cluster_filesystem_used_percent": "说明：文件系统使用率（%），用于识别空间紧张挂载点。",
    }
    return desc_map.get(mname, "")

timeseries_dir = input_dir / "timeseries"
prom_files = []
if timeseries_dir.exists():
    for p in timeseries_dir.glob("*.prom"):
        prom_files.append(p)
    sub = timeseries_dir / "business_table_writes" / "business_table_writes_timeseries.prom"
    if sub.exists():
        prom_files.append(sub)

plots_root = input_dir / "timeseries_plots"
ensure_dir(plots_root)

file_metrics = {}
for pf in prom_files:
    metrics = {}
    try:
        with pf.open("r", encoding="utf-8") as f:
            for line in f:
                parsed = parse_prom_line(line)
                if not parsed:
                    continue
                metric, labels, value, ts = parsed
                if ts is None:
                    continue
                dt = datetime.fromtimestamp(ts / 1000.0)
                series_key = label_repr(labels)
                metrics.setdefault(metric, {}).setdefault(series_key, []).append((dt, value))
    except Exception:
        continue
    for mname in metrics:
        for sk in metrics[mname]:
            metrics[mname][sk].sort(key=lambda x: x[0])
    file_metrics[str(pf)] = metrics

node_usage_metrics = file_metrics.get(str(timeseries_dir / "cluster_node_usage_timeseries.prom"), {})
filesystem_metrics = file_metrics.get(str(timeseries_dir / "cluster_filesystem_usage_timeseries.prom"), {})
filesystem_total_series = filesystem_metrics.get("sr_migration_cluster_filesystem_total_bytes", {})

def pick_filesystem_device(total_series, instance):
    max_total = None
    selected_device = None
    for key, points in total_series.items():
        inst, dev = parse_instance_device(key)
        if inst != instance:
            continue
        latest = series_latest(points)
        if latest is None:
            continue
        if max_total is None or latest > max_total:
            max_total = latest
            selected_device = dev
    return selected_device, max_total

def normalize_device_name(device):
    if not device:
        return device
    dev = str(device)
    if dev.startswith("/dev/"):
        dev = dev[len("/dev/"):]
    if dev.startswith("mapper/"):
        dev = dev[len("mapper/"):]
    return dev

def map_device(device):
    base = normalize_device_name(device)
    if not base:
        return device
    return device_mapper.get(base, base)

cpu_summary_rows = []
memory_summary_rows = []
storage_summary_rows = []
net_summary_rows = []
for r in k8s_nodes:
    node_ip = get_value(r, "internal_ip")
    cpu_summary_rows.append([
        node_ip,
        get_value(r, "cpu_allocatable"),
        parse_cpu_to_cores(get_value(r, "cpu_requests")),
        parse_cpu_to_cores(get_value(r, "cpu_limits")),
        series_avg(get_series_points(node_usage_metrics, "sr_migration_cluster_node_cpu_usage_percent_avg", node_ip)),
        series_max(get_series_points(node_usage_metrics, "sr_migration_cluster_node_cpu_usage_percent_max", node_ip)),
    ])
    memory_summary_rows.append([
        node_ip,
        to_gb_from_kib(get_value(r, "memory_allocatable")),
        to_gb_from_mem(get_value(r, "memory_requests")),
        to_gb_from_mem(get_value(r, "memory_limits")),
        series_avg(get_series_points(node_usage_metrics, "sr_migration_cluster_node_memory_usage_percent_avg", node_ip)),
        series_max(get_series_points(node_usage_metrics, "sr_migration_cluster_node_memory_usage_percent_max", node_ip)),
    ])
    device, total_latest = pick_filesystem_device(filesystem_total_series, node_ip)
    # todo 增加device的debug日志
    free_points = get_series_points(filesystem_metrics, "sr_migration_cluster_filesystem_free_bytes", node_ip, device)
    free_latest = series_latest(free_points)
    free_percent = ""
    if free_latest is not None and total_latest not in (None, 0):
        free_percent = format_number((free_latest / total_latest) * 100.0)
    mapped_device = map_device(device)
    disk_io_util_max_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_io_util_percent_max", node_ip, mapped_device)
    disk_io_util_avg_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_io_util_percent_avg", node_ip, mapped_device)
    disk_read_await_max_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_read_await_ms_max", node_ip, mapped_device)
    disk_read_await_avg_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_read_await_ms_avg", node_ip, mapped_device)
    disk_write_await_max_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_write_await_ms_max", node_ip, mapped_device)
    disk_write_await_avg_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_write_await_ms_avg", node_ip, mapped_device)
    disk_read_mbps_avg_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_read_mbps_avg", node_ip, mapped_device)
    disk_read_mbps_max_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_read_mbps_max", node_ip, mapped_device)
    disk_write_mbps_avg_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_write_mbps_avg", node_ip, mapped_device)
    disk_write_mbps_max_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_write_mbps_max", node_ip, mapped_device)
    disk_read_iops_avg_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_read_iops_avg", node_ip, mapped_device)
    disk_read_iops_max_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_read_iops_max", node_ip, mapped_device)
    disk_write_iops_avg_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_write_iops_avg", node_ip, mapped_device)
    disk_write_iops_max_points = get_series_points(node_usage_metrics, "sr_migration_cluster_node_disk_write_iops_max", node_ip, mapped_device)
    disk_values = [
        format_avg_max(disk_io_util_avg_points, disk_io_util_max_points),
        format_avg_max(disk_read_await_avg_points, disk_read_await_max_points),
        format_avg_max(disk_write_await_avg_points, disk_write_await_max_points),
        format_avg_max(disk_read_mbps_avg_points, disk_read_mbps_max_points),
        format_avg_max(disk_write_mbps_avg_points, disk_write_mbps_max_points),
        format_avg_max(disk_read_iops_avg_points, disk_read_iops_max_points),
        format_avg_max(disk_write_iops_avg_points, disk_write_iops_max_points),
    ]
    if all(v == "" for v in disk_values):
        keys = sorted(node_usage_metrics.keys())
        sys.stderr.write("DEBUG: storage metrics empty for node_ip={} device={} metrics_count={}\n".format(node_ip, device or "", len(keys)))
        for metric_name in (
            "sr_migration_cluster_node_disk_io_util_percent_avg",
            "sr_migration_cluster_node_disk_io_util_percent_max",
            "sr_migration_cluster_node_disk_read_await_ms_avg",
            "sr_migration_cluster_node_disk_read_await_ms_max",
            "sr_migration_cluster_node_disk_write_await_ms_avg",
            "sr_migration_cluster_node_disk_write_await_ms_max",
            "sr_migration_cluster_node_disk_read_mbps_avg",
            "sr_migration_cluster_node_disk_read_mbps_max",
            "sr_migration_cluster_node_disk_write_mbps_avg",
            "sr_migration_cluster_node_disk_write_mbps_max",
            "sr_migration_cluster_node_disk_read_iops_avg",
            "sr_migration_cluster_node_disk_read_iops_max",
            "sr_migration_cluster_node_disk_write_iops_avg",
            "sr_migration_cluster_node_disk_write_iops_max",
        ):
            series_map = node_usage_metrics.get(metric_name, {})
            matched_keys = [k for k in series_map.keys() if node_ip in k]
            sys.stderr.write("DEBUG: metric={} matched_keys={}\n".format(metric_name, ",".join(matched_keys)))
    storage_summary_rows.append([
        node_ip,
        to_gb(total_latest) if total_latest is not None else "",
        to_gb(free_latest) if free_latest is not None else "",
        free_percent,
        disk_values[0],
        disk_values[1],
        disk_values[2],
        disk_values[3],
        disk_values[4],
        disk_values[5],
        disk_values[6],
    ])
    net_summary_rows.append([
        node_ip,
        series_avg(get_series_points(node_usage_metrics, "sr_migration_cluster_node_net_rx_mbps_avg", node_ip)),
        series_max(get_series_points(node_usage_metrics, "sr_migration_cluster_node_net_rx_mbps_max", node_ip)),
        series_avg(get_series_points(node_usage_metrics, "sr_migration_cluster_node_net_tx_mbps_avg", node_ip)),
        series_max(get_series_points(node_usage_metrics, "sr_migration_cluster_node_net_tx_mbps_max", node_ip)),
    ])

timeseries_sections = []
for pf in prom_files:
    cat = category_for_file(pf.name)
    cat_dir = plots_root / cat
    ensure_dir(cat_dir)
    metrics = file_metrics.get(str(pf), {})
    if not metrics:
        continue
    section = {"title": cat, "desc": "", "images": []}
    if cat == "节点资源使用":
        section["desc"] = "说明：展示节点CPU、内存、磁盘与网络资源的平均与峰值变化趋势。"
    elif cat == "ClickHouse关键指标":
        section["desc"] = "说明：展示ClickHouse核心运行指标随时间的变化，用于评估负载与稳定性。"
    elif cat == "节点文件系统":
        section["desc"] = "说明：展示节点文件系统容量与使用情况的变化趋势。"
    elif cat == "CK Pod资源":
        section["desc"] = "说明：展示CK Pod级别的资源使用情况与波动。"
    elif cat == "业务表写入":
        section["desc"] = "说明：展示业务表写入量随时间的变化趋势。"
    selected_raw_device = {}
    selected_mapped_device = {}
    for r in k8s_nodes:
        ip = get_value(r, "internal_ip")
        dev, _ = pick_filesystem_device(filesystem_total_series, ip)
        if dev:
            selected_raw_device[ip] = dev
            selected_mapped_device[ip] = map_device(dev)
    for mname, series_map in metrics.items():
        name_lower = mname.lower()
        if "swap_usage" in name_lower:
            continue
        if name_lower.startswith("sr_migration_clickhouse_metrics_") and "connections" in name_lower and "tcp_connections" not in name_lower:
            continue
        if name_lower in ("sr_migration_cluster_node_disk_await_ms_avg", "sr_migration_cluster_node_disk_await_ms_max"):
            continue
        name_lower = mname.lower()
        y_label = "值"
        if ("memory" in name_lower and ("bytes" in name_lower or name_lower.endswith("_bytes") or "memory_tracking" in name_lower)):
            scaled_map = {}
            for sk, points in series_map.items():
                scaled_map[sk] = [(x, y / (1024.0 ** 3)) for x, y in points]
            series_map = scaled_map
            y_label = "值(GB)"
        filtered_map = {}
        if "disk_usage_percent" in name_lower and "cluster_node" in name_lower:
            for sk, points in series_map.items():
                inst, dev = parse_instance_device(sk)
                if inst and (inst in selected_raw_device):
                    if dev is None or dev == "" or dev == selected_raw_device.get(inst):
                        filtered_map[sk] = points
        elif any(k in name_lower for k in ["disk_read_mbps", "disk_write_mbps", "disk_read_iops", "disk_write_iops", "disk_read_await_ms", "disk_write_await_ms", "disk_io_util_percent"]):
            for sk, points in series_map.items():
                inst, dev = parse_instance_device(sk)
                target = selected_mapped_device.get(inst)
                if inst and dev and target and dev == target:
                    filtered_map[sk] = points
        else:
            filtered_map = series_map
        series_map = filtered_map
        is_business_writes = cat == "业务表写入"
        if is_business_writes:
            latest_times = [points[-1][0] for points in series_map.values() if points]
            if latest_times:
                window_start = max(latest_times) - timedelta(days=3)
                filtered_map = {}
                for sk, points in series_map.items():
                    filtered_points = [(x, y) for x, y in points if x >= window_start]
                    if filtered_points:
                        filtered_map[sk] = filtered_points
                series_map = filtered_map
        def last_value(points):
            return points[-1][1] if points else float("-inf")
        sorted_series = sorted(series_map.items(), key=lambda kv: last_value(kv[1]), reverse=True)[:10]
        plt.figure(figsize=(10, 5))
        ax = plt.gca()
        try:
            import matplotlib.dates as mdates
            locator = mdates.HourLocator(interval=3)
            formatter = mdates.DateFormatter("%m-%d %H:00")
            ax.xaxis.set_major_locator(locator)
            ax.xaxis.set_major_formatter(formatter)
            ax.tick_params(axis="x", labelsize=6)
            plt.setp(ax.get_xticklabels(), rotation=90, ha="center", va="center")
        except Exception:
            pass
        for sk, points in sorted_series:
            xs = [p[0] for p in points]
            ys = [p[1] for p in points]
            if xs and ys:
                plt.plot(xs, ys, label=sk)
        if font_prop:
            plt.title("{} ({})".format(mname, pf.name), fontproperties=font_prop)
            plt.xlabel("时间", fontproperties=font_prop)
            plt.ylabel(y_label, fontproperties=font_prop)
            for label in ax.get_yticklabels():
                label.set_fontproperties(font_prop)
        else:
            plt.title("{} ({})".format(mname, pf.name))
            plt.xlabel("时间")
            plt.ylabel(y_label)
        plt.legend(loc="best", fontsize=8)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        out_path = cat_dir / ("{}.png".format(mname))
        try:
            plt.savefig(str(out_path))
        except Exception:
            pass
        finally:
            plt.close()
        section["images"].append({"path": out_path, "desc": metric_desc(mname, y_label)})
    timeseries_sections.append(section)

pdf_path = input_dir / "report.pdf"

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.platypus import PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from PIL import Image as PILImage

svg2rlg = None
renderPM = None
try:
    from svglib.svglib import svg2rlg
    from reportlab.graphics import renderPM
except Exception:
    svg2rlg = None
    renderPM = None


styles = getSampleStyleSheet()
pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
style_h1 = styles["Heading1"].clone("Heading1CJK")
style_h2 = styles["Heading2"].clone("Heading2CJK")
style_body = styles["BodyText"].clone("BodyTextCJK")
style_table = styles["BodyText"].clone("TableTextCJK")
style_h1.fontName = "STSong-Light"
style_h2.fontName = "STSong-Light"
style_body.fontName = "STSong-Light"
style_table.fontName = "STSong-Light"
style_table.fontSize = 8
style_table.leading = 10
def truncate_text(text, max_width, font_name, font_size):
    try:
        from reportlab.pdfbase import pdfmetrics
        s = str(text)
        w = pdfmetrics.stringWidth(s, font_name, font_size)
        if w <= max_width:
            return s
        ell = "…"
        ell_w = pdfmetrics.stringWidth(ell, font_name, font_size)
        target = max(0.0, max_width - ell_w)
        lo, hi = 0, len(s)
        best = ""
        while lo <= hi:
            mid = (lo + hi) // 2
            t = s[:mid]
            tw = pdfmetrics.stringWidth(t, font_name, font_size)
            if tw <= target:
                best = t
                lo = mid + 1
            else:
                hi = mid - 1
        return best + ell
    except Exception:
        return str(text)

class PdfDoc(SimpleDocTemplate):
    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            text = flowable.getPlainText()
            if flowable.style.name == "Heading1CJK":
                self.notify("TOCEntry", (0, text, self.page))
            if flowable.style.name == "Heading2CJK":
                self.notify("TOCEntry", (1, text, self.page))

doc = PdfDoc(str(pdf_path), pagesize=A4, leftMargin=36, rightMargin=36, topMargin=36, bottomMargin=36)
flow = []

def add_paragraph(text):
    flow.append(Paragraph(text, style_body))
    flow.append(Spacer(1, 8))

def add_heading(text):
    flow.append(Paragraph(text, style_h2))
    flow.append(Spacer(1, 8))

def add_heading1(text):
    flow.append(Paragraph(text, style_h1))
    flow.append(Spacer(1, 10))

def add_table(table_rows, wrap_header=False, wrap_cols=None):
    if not table_rows:
        return
    max_width = A4[0] - 72
    col_count = len(table_rows[0])
    col_max = [1] * col_count
    for row in table_rows:
        for i in range(col_count):
            col_max[i] = max(col_max[i], len(str(row[i])))
    weights = [max(6, min(60, v)) for v in col_max]
    total_w = float(sum(weights))
    col_widths = [max_width * (w / total_w) for w in weights]
    font_name = style_table.fontName
    base_font_size = style_table.fontSize
    min_font_size = 5.0
    target_font_size = base_font_size
    try:
        from reportlab.pdfbase import pdfmetrics
        for row in table_rows:
            for i, cell in enumerate(row):
                text = str(cell)
                if not text:
                    continue
                avail = max(1.0, col_widths[i] - 4)
                text_width = pdfmetrics.stringWidth(text, font_name, base_font_size)
                if text_width > 0:
                    candidate = base_font_size * (avail / text_width)
                    if candidate < target_font_size:
                        target_font_size = candidate
        if target_font_size < min_font_size:
            target_font_size = min_font_size
        if target_font_size > base_font_size:
            target_font_size = base_font_size
    except Exception:
        target_font_size = base_font_size
    if wrap_cols is None:
        wrap_cols = []
    wrap_style = style_table.clone("TableWrap")
    wrap_style.wordWrap = "CJK"
    table_cells = []
    for r_idx, row in enumerate(table_rows):
        row_cells = []
        for i, cell in enumerate(row):
            text = str(cell)
            if (wrap_header and r_idx == 0) or (i in wrap_cols and r_idx > 0):
                row_cells.append(Paragraph(escape(text).replace("\n", "<br/>"), wrap_style))
            else:
                row_cells.append(text)
        table_cells.append(row_cells)
    table = Table(table_cells, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, -1), "STSong-Light"),
        ("FONTSIZE", (0, 0), (-1, -1), target_font_size),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))
    flow.append(table)
    flow.append(Spacer(1, 10))

def add_image(image_path):
    try:
        if image_path.suffix.lower() == ".svg":
            if svg2rlg and renderPM:
                drawing = svg2rlg(str(image_path))
                if drawing:
                    png_path = image_path.with_suffix(".png")
                    renderPM.drawToFile(drawing, str(png_path), fmt="PNG")
                    image_path = png_path
                else:
                    sys.stderr.write("ERROR: SVG图片无法渲染，请安装svglib或matplotlib生成PNG。\n")
                    add_paragraph("图片加载失败：{}".format(image_path))
                    return
            else:
                sys.stderr.write("ERROR: SVG图片无法渲染，请安装svglib或matplotlib生成PNG。\n")
                add_paragraph("图片加载失败：{}".format(image_path))
                return
        with PILImage.open(image_path) as im:
            width, height = im.size
        max_width = A4[0] - 72
        max_height = A4[1] - 72
        scale = min(1.0, max_width / float(width), max_height / float(height))
        img = Image(str(image_path), width=width * scale, height=height * scale)
        flow.append(img)
        flow.append(Spacer(1, 12))
    except Exception:
        add_paragraph("图片加载失败：{}".format(image_path))

toc = TableOfContents()
toc.levelStyles = [style_h1, style_h2]
add_heading1("目录")
flow.append(toc)
flow.append(PageBreak())

add_heading1("节点概要")
add_heading("CPU指令集支持")
add_table([["项目", "值"], ["CPU指令集", cpu_value]])

add_heading("K8S节点信息")
add_table([
    ["name", "internal_ip", "os_image", "kernel_version", "cpu_capacity", "memory_capacity(GB)", "cpu_allocatable", "memory_allocatable(GB)", "cpu_requests",  "cpu_limits",  "memory_requests(GB)",  "memory_limits(GB)",  "creation_timestamp"]
] + node_rows)

add_heading("CPU概要")
add_table([
    ["节点IP", "可分配CPU", "CPU Requests", "CPU Limits", "CPU使用率均值(%)", "CPU使用率最大(%)"]
 ] + cpu_summary_rows)

add_heading("内存概要")
add_table([
    ["节点IP", "可分配内存(GB)", "内存Requests(GB)", "内存Limits(GB)", "内存使用率均值(%)", "内存使用率最大(%)"]
 ] + memory_summary_rows)

add_heading("存储概要")
add_table([
    ["节点IP", "文件系统总容量(GB)", "文件系统可用容量(GB)", "可用容量占比(%)", "磁盘IO利用率(均值/最大,%)", "磁盘读时延(均值/最大,ms)", "磁盘写时延(均值/最大,ms)", "磁盘读吞吐(均值/最大,MB/s)", "磁盘写吞吐(均值/最大,MB/s)", "磁盘读IOPS(均值/最大,IOPS)", "磁盘写IOPS(均值/最大,IOPS)"]
 ] + storage_summary_rows, wrap_header=True)

add_heading("网口概要")
add_table([
    ["节点IP", "网络接收均值(MB/s)", "网络接收最大(MB/s)", "网络发送均值(MB/s)", "网络发送最大(MB/s)"]
 ] + net_summary_rows)

add_heading("存储卷容量(GB)")
add_table([
    ["node_host", "name", "path", "total_space_GB", "free_space_GB", "keep_free_space_GB"]
] + volume_rows)

add_heading1("business表画像")
add_heading("业务TTL非180天")
add_table([["database", "table", "ttl_expression", "ttl_value"]] + ttl_rows)

add_heading("business库数据量统计")
add_table([
    ["指标", "数量"],
    ["数据量为0的表数量", str(business_zero)],
    ["数据量不为0的表数量", str(business_nonzero)],
])

add_heading("business库按未压缩大小降序Top10")
add_table([["database", "table", "engine", "total_rows", "compressed_size_GB", "uncompressed_size_GB"]] + top10_rows)

add_heading("非人工用户组查询时间范围PXX Top10")
add_table([["table_name", "p50_days", "p80_days", "p90_days", "p95_days", "p99_days", "p100_days"]] + time_rows)

add_heading1("其他表")
add_heading("非business库表列表")
add_table([["database", "table"]] + non_business)

add_heading("视图DDL")
add_table([["database", "view", "engine", "create_table_query_one_line"]] + views_rows, wrap_header=True, wrap_cols=[3])

add_heading1("时序图")
for section in timeseries_sections:
    add_heading(section["title"])
    if section["desc"]:
        add_paragraph(section["desc"])
    for img_path in section["images"]:
        path = img_path["path"]
        desc = img_path["desc"]
        add_image(path)
        if desc:
            add_paragraph(desc)

doc.multiBuild(flow)
