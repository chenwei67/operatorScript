#!/usr/bin/env python3
import csv
import re
import sys
from pathlib import Path
from datetime import datetime, timedelta

input_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./migration_report")
pdf_path = input_dir / "report.pdf"
pdf_path.parent.mkdir(parents=True, exist_ok=True)

def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def to_gb(value):
    try:
        return "{:.2f}".format(float(value) / (1024 ** 3))
    except Exception:
        return "0.00"

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
node_rows = [
    [
        r["name"],
        r["internal_ip"],
        r["os_image"],
        r["kernel_version"],
        r["cpu_capacity"],
        to_gb_from_kib(r["memory_capacity"]),
        r["cpu_allocatable"],
        to_gb_from_kib(r["memory_allocatable"]),
        r["creation_timestamp"],
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
business_rows = [r for r in table_stats if r["database"] == "business"]
business_zero = sum(1 for r in business_rows if int(float(r["total_rows"])) == 0)
business_nonzero = sum(1 for r in business_rows if int(float(r["total_rows"])) > 0)

top10 = sorted(
    business_rows,
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

time_range = read_csv(input_dir / "timeseries/query_time_range_distribution_strict_by_user_group.csv")
non_human = [r for r in time_range if r["user_group"] == "__NON_HUMAN__"]
non_human_sorted = sorted(non_human, key=lambda r: float(r["p99_days"]), reverse=True)[:10]
time_rows = [
    [
        r["table_name"],
        r["p50_days"],
        r["p80_days"],
        r["p90_days"],
        r["p95_days"],
        r["p99_days"],
    ]
    for r in non_human_sorted
]

non_business = [[r["database"], r["table"]] for r in table_stats if r["database"] != "business"]
views = read_csv(input_dir / "views_ddl.csv")
views_rows = [[r["database"], r["view"], r["engine"], r["create_table_query_one_line"]] for r in views]

plot_mode = "svg"
plt = None
try:
    import matplotlib
    import matplotlib.pyplot as plt
    matplotlib.rcParams["font.sans-serif"] = ["PingFang SC", "Heiti SC", "STHeiti", "Arial Unicode MS", "SimHei"]
    matplotlib.rcParams["axes.unicode_minus"] = False
    plot_mode = "matplotlib"
except Exception:
    plot_mode = "svg"

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

def render_svg(series_list, out_path, title, y_label, x_tick_mode=None, x_tick_rotation=-30):
    width = 900
    height = 460
    padding_left = 80
    padding_right = 180
    padding_top = 40
    padding_bottom = 90
    plot_width = width - padding_left - padding_right
    plot_height = height - padding_top - padding_bottom
    all_x = []
    all_y = []
    for _, points in series_list:
        for x, y in points:
            all_x.append(x)
            all_y.append(y)
    if not all_x or not all_y:
        return
    min_x, max_x = min(all_x), max(all_x)
    min_y, max_y = min(all_y), max(all_y)
    if max_y == min_y:
        max_y = min_y + 1.0
    if max_x == min_x:
        max_x = min_x + 1.0
    colors = [
        "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd",
        "#8c564b", "#e377c2", "#7f7f7f", "#bcbd22", "#17becf",
    ]
    lines = []
    lines.append('<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}">'.format(width, height))
    lines.append('<rect width="100%" height="100%" fill="white"/>')
    lines.append('<text x="{}" y="{}" font-size="16" font-family="Arial">{}</text>'.format(padding_left, 24, title))
    lines.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#666666"/>'.format(padding_left, height - padding_bottom, width - padding_right, height - padding_bottom))
    lines.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#666666"/>'.format(padding_left, padding_top, padding_left, height - padding_bottom))
    x_tick_count = 6
    for i in range(x_tick_count + 1):
        frac = float(i) / float(x_tick_count)
        dt_tick = min_x + (max_x - min_x) * frac
        px = padding_left + frac * plot_width
        lines.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#666666"/>'.format(px, height - padding_bottom, px, height - padding_bottom + 8))
        lines.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#eeeeee"/>'.format(px, padding_top, px, height - padding_bottom))
        if x_tick_mode == "hour":
            dt_tick = dt_tick.replace(minute=0, second=0, microsecond=0)
            label = dt_tick.strftime("%m-%d %H:00")
        else:
            label = dt_tick.strftime("%m-%d %H:%M")
        lines.append('<text x="{}" y="{}" font-size="7" font-family="Arial" text-anchor="middle" transform="rotate({} {} {})">{}</text>'.format(px, height - padding_bottom + 28, x_tick_rotation, px, height - padding_bottom + 28, label))
    y_tick_count = 5
    for i in range(y_tick_count + 1):
        frac = float(i) / float(y_tick_count)
        val = min_y + (max_y - min_y) * frac
        py = height - padding_bottom - frac * plot_height
        lines.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#666666"/>'.format(padding_left - 8, py, padding_left, py))
        lines.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#eeeeee"/>'.format(padding_left, py, width - padding_right, py))
        label = "{:.2f}".format(val)
        lines.append('<text x="{}" y="{}" font-size="12" font-family="Arial" text-anchor="end">{}</text>'.format(padding_left - 12, py + 4, label))
    lines.append('<text x="{}" y="{}" font-size="12" font-family="Arial" text-anchor="middle">时间</text>'.format(padding_left + plot_width / 2.0, height - 18))
    lines.append('<text x="{}" y="{}" font-size="12" font-family="Arial" text-anchor="middle" transform="rotate(-90 {} {})">{}</text>'.format(18, padding_top + plot_height / 2.0, 18, padding_top + plot_height / 2.0, y_label))
    for idx, (label, points) in enumerate(series_list):
        color = colors[idx % len(colors)]
        coords = []
        for x, y in points:
            x_norm = (x - min_x) / (max_x - min_x)
            y_norm = (y - min_y) / (max_y - min_y)
            px = padding_left + x_norm * plot_width
            py = height - padding_bottom - y_norm * plot_height
            coords.append("{},{}".format(px, py))
        lines.append('<polyline fill="none" stroke="{}" stroke-width="2" points="{}"/>'.format(color, " ".join(coords)))
    legend_x = width - padding_right + 10
    legend_y = padding_top + 10
    for idx, (label, _) in enumerate(series_list):
        color = colors[idx % len(colors)]
        y = legend_y + idx * 18
        lines.append('<rect x="{}" y="{}" width="10" height="10" fill="{}"/>'.format(legend_x, y - 8, color))
        lines.append('<text x="{}" y="{}" font-size="11" font-family="Arial">{}</text>'.format(legend_x + 14, y, label))
    lines.append("</svg>")
    out_path.write_text("\n".join(lines), encoding="utf-8")

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
        "sr_migration_ck_pod_disk_read_mbps_avg": "说明：CK Pod按device统计的磁盘读速率平均值（MB/s），反映磁盘读吞吐。",
        "sr_migration_ck_pod_disk_read_mbps_max": "说明：CK Pod按device统计的磁盘读速率峰值（MB/s），用于识别读突发。",
        "sr_migration_ck_pod_disk_write_mbps_avg": "说明：CK Pod按device统计的磁盘写速率平均值（MB/s），反映磁盘写吞吐。",
        "sr_migration_ck_pod_disk_write_mbps_max": "说明：CK Pod按device统计的磁盘写速率峰值（MB/s），用于识别写突发。",
        "sr_migration_ck_pod_disk_read_iops_avg": "说明：CK Pod按device统计的磁盘读IOPS平均值，用于观察读请求压力。",
        "sr_migration_ck_pod_disk_read_iops_max": "说明：CK Pod按device统计的磁盘读IOPS峰值，用于识别读突发。",
        "sr_migration_ck_pod_disk_write_iops_avg": "说明：CK Pod按device统计的磁盘写IOPS平均值，用于观察写请求压力。",
        "sr_migration_ck_pod_disk_write_iops_max": "说明：CK Pod按device统计的磁盘写IOPS峰值，用于识别写突发。",
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
        "sr_migration_cluster_node_disk_await_ms_avg": "说明：节点按device统计的磁盘IO等待时延平均值（ms），反映IO响应情况。",
        "sr_migration_cluster_node_disk_await_ms_max": "说明：节点按device统计的磁盘IO等待时延峰值（ms），用于识别IO抖动。",
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
    for mname, series_map in metrics.items():
        name_lower = mname.lower()
        if "swap_usage" in name_lower:
            continue
        if name_lower.startswith("sr_migration_clickhouse_metrics_") and "connections" in name_lower and "tcp_connections" not in name_lower:
            continue
        name_lower = mname.lower()
        y_label = "值"
        if ("memory" in name_lower and ("bytes" in name_lower or name_lower.endswith("_bytes") or "memory_tracking" in name_lower)):
            scaled_map = {}
            for sk, points in series_map.items():
                scaled_map[sk] = [(x, y / (1024.0 ** 3)) for x, y in points]
            series_map = scaled_map
            y_label = "值(GB)"
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
        if plot_mode == "matplotlib":
            plt.figure(figsize=(10, 5))
            try:
                import matplotlib.dates as mdates
                ax = plt.gca()
                if is_business_writes:
                    locator = mdates.HourLocator(interval=1)
                    formatter = mdates.DateFormatter("%m-%d %H:00")
                else:
                    locator = mdates.AutoDateLocator()
                    formatter = mdates.ConciseDateFormatter(locator)
                ax.xaxis.set_major_locator(locator)
                ax.xaxis.set_major_formatter(formatter)
                ax.tick_params(axis="x", labelsize=8)
                if is_business_writes:
                    plt.setp(ax.get_xticklabels(), rotation=90, ha="center", va="center")
            except Exception:
                pass
            for sk, points in sorted_series:
                xs = [p[0] for p in points]
                ys = [p[1] for p in points]
                if xs and ys:
                    plt.plot(xs, ys, label=sk)
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
        else:
            out_path = cat_dir / ("{}.svg".format(mname))
            render_svg(sorted_series, out_path, "{} ({})".format(mname, pf.name), y_label, x_tick_mode="hour" if is_business_writes else None, x_tick_rotation=90 if is_business_writes else -30)
        section["images"].append({"path": out_path, "desc": metric_desc(mname, y_label)})
    timeseries_sections.append(section)

pdf_path = input_dir / "report.pdf"
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
    from reportlab.platypus.tableofcontents import TableOfContents
    from reportlab.platypus import PageBreak
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.cidfonts import UnicodeCIDFont
    from PIL import Image as PILImage
except Exception:
    sys.exit(0)

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

def add_table(table_rows):
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
    table_cells = []
    for r_idx, row in enumerate(table_rows):
        row_cells = []
        for cell in row:
            row_cells.append(Paragraph(str(cell), style_table))
        table_cells.append(row_cells)
    table = Table(table_cells, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "STSong-Light"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    flow.append(table)
    flow.append(Spacer(1, 10))

def add_image(image_path):
    try:
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
    ["name", "internal_ip", "os_image", "kernel_version", "cpu_capacity", "memory_capacity_GB", "cpu_allocatable", "memory_allocatable_GB", "creation_timestamp"]
] + node_rows)

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
add_table([["table_name", "p50_days", "p80_days", "p90_days", "p95_days", "p99_days"]] + time_rows)

add_heading1("其他表")
add_heading("非business库表列表")
add_table([["database", "table"]] + non_business)

add_heading("视图DDL")
add_table([["database", "view", "engine", "create_table_query_one_line"]] + views_rows)

add_heading1("时序图")
for section in timeseries_sections:
    add_heading(section["title"])
    if section["desc"]:
        add_paragraph(section["desc"])
    for img_path in section["images"]:
        path = img_path["path"]
        desc = img_path["desc"]
        if path.suffix.lower() in (".png", ".jpg", ".jpeg"):
            add_image(path)
        else:
            add_paragraph("图片格式不支持：{}".format(path.name))
        if desc:
            add_paragraph(desc)

doc.multiBuild(flow)
