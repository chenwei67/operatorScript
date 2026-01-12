# collect.sh 指标采集清单（CK -> SR 迁移）

默认输出目录：

- `OUTPUT_DIR` 未指定时为 `$(pwd)/output`（见脚本参数处理逻辑）
- 目录结构：`$OUTPUT_DIR/`、`$OUTPUT_DIR/timeseries/`、`$OUTPUT_DIR/snapshots/`

压力风险说明（粗略）：

- 高：可能对线上 ClickHouse（尤其是 `system.query_log`/业务大表）造成明显 CPU/IO/内存压力
- 中：对 ClickHouse 有可见压力，但通常可通过缩短窗口/限制线程缓解
- 低：通常影响有限（但在超大集群/极端基数下仍可能变慢）

## 一、汇总入口与归档

| 采集内容/指标       | 统计方式或公式（脚本口径）                                                                                                            | 导出位置（相对 `$OUTPUT_DIR` 或 JSON 字段） | 压力风险                       | 在 CK -> SR 迁移中的作用                                   |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ------------------------------ | ---------------------------------------------------------- |
| 汇总 JSON（总入口） | 汇总各类 CSV/Prom 路径与摘要信息（cluster_overview/tables/schemas/traffic/resources/meta）                                            | `migration_metrics.json`                    | 低                             | 统一入口，便于自动化解析与归档，作为迁移评估报告的数据索引 |
| 归档压缩包（可选）  | `tar -czf "${OUTPUT_DIR}.tar.gz"`，成功后删除原目录                                    | `${OUTPUT_DIR}.tar.gz`（与输出目录同级） | 低                                            | 便于跨环境传输、留档与离线分析 |                                                            |

## 二、集群规模与硬件信息

| 采集内容/指标                                 | 统计方式或公式（脚本口径）                                                                                                                                                                                                                       | 导出位置（相对 `$OUTPUT_DIR` 或 JSON 字段）                                                                       | 压力风险                | 在 CK -> SR 迁移中的作用                                                                       |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------- |
| 集群节点数                                    | `kubectl get nodes --no-headers \| wc -l`                                                                                                                                                                                                       | `migration_metrics.json.cluster_overview.cluster_node_count`                                                      | 低                      | 迁移容量与规模评估的“最基础”输入（SR 侧节点规模、分片规划、并发迁移度）                      |
| CHI 分片/副本与期望节点数                     | 从 `kubectl get chi ... jsonpath` 取 `shardsCount/replicasCount`，并计算 `shards*replicas`                                                                                                                                                 | `migration_metrics.json.cluster_overview.chi_shards_count` / `chi_replicas_count` / `chi_expected_node_count` | 低                      | 还原 CK 当前集群拓扑，为 SR 侧分片与副本设计提供对照基线                                       |
| K8s 节点硬件清单（核数/内存）                 | `kubectl get nodes -o jsonpath ...` 导出 `cpu_capacity/memory_capacity` 及 allocatable                                                                                                                                                       | `snapshots/cluster_k8s_nodes.csv`                                                                                 | 低                      | 清晰看到“有多少节点、每个节点多少核/多少内存”，用于 SR 侧硬件等价或扩缩容计算                |
| K8s 节点磁盘容量与使用量（来自 VM）           | VictoriaMetrics `api/v1/query` 拉 `node_filesystem_size_bytes/free_bytes`，按 node+mountpoint 计算 `used_bytes/used_percent`（过滤 tmpfs/overlay 等）                                                                                      | `snapshots/cluster_node_disk_usage.csv`                                                                           | 低（对 CK）/中（对 VM） | 获得全节点磁盘水位（容量/使用率），用于 SR 容量规划、迁移窗口风险评估与限流策略                |
| 执行节点硬件快照（CPU 核数/内存/磁盘/负载等） | 从 `/proc/meminfo`、`/proc/loadavg`、`/proc/cpuinfo`、`df`、`/proc/sys/fs/file-nr`、`/proc/net/sockstat` 采集：`cpu_cores/memory_total_bytes/memory_used_bytes/disk_total_bytes/disk_used_bytes/load_avg/cpu_flags/swap/fd/tcp` 等 | `migration_metrics.json.resources.node_level.*`                                                                   | 低                      | 采集脚本运行环境的资源水位（是否 CPU/内存/FD/连接紧张），辅助判断迁移/采集本身的可执行性与风险 |

## 三、部署与配置（可复现性/对齐）

| 采集内容/指标            | 统计方式或公式（脚本口径）                                                   | 导出位置（相对 `$OUTPUT_DIR` 或 JSON 字段）          | 压力风险 | 在 CK -> SR 迁移中的作用                                                   |
| ------------------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------ | -------- | -------------------------------------------------------------------------- |
| Helm release 用户 values | `helm list` 后对每个 release 执行 `helm get values`                      | `helm/<release>.yaml`                                | 低       | 还原线上部署参数（资源、存储、镜像、配置），用于 SR 侧对齐部署与排障复现   |
| ClickHouse 版本          | `SELECT version()`                                                         | `migration_metrics.json.cluster_overview.ck_version` | 低       | 不同 CK 版本 system 表字段/函数不同，影响 query_log 采集口径与迁移兼容策略 |
| system.settings          | `SELECT name,value,changed,description FROM system.settings ORDER BY name` | `snapshots/system_settings.csv`                      | 低       | 参数基线对照（并发、合并、内存等），迁移到 SR 后用于等价调参或差异解释     |
| system.build_options     | `SELECT name,value FROM system.build_options ORDER BY name`                | `snapshots/system_build_options.csv`                 | 低       | 编译特性差异可能导致行为不同，便于迁移后问题定位                           |

## 四、表结构与数据体量

| 采集内容/指标                    | 统计方式或公式（脚本口径）                                                                                                                                                   | 导出位置（相对 `$OUTPUT_DIR` 或 JSON 字段） | 压力风险 | 在 CK -> SR 迁移中的作用                                    |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | -------- | ----------------------------------------------------------- |
| 全量表统计（行数/压缩/解压大小） | `clusterAllReplicas(system.tables)` 取表清单；LEFT JOIN `clusterAllReplicas(system.parts)`（限定 replica_num=1）聚合 `sum(rows/bytes_on_disk/data_uncompressed_bytes)` | `table_stats.csv`                           | 中       | 盘点迁移规模与热点大表，决定分批迁移顺序、SR 容量与分片规划 |
| 全量表 schema（列级）            | `system.columns` 导出 `database/table/column/type/default_*`                                                                                                             | `table_schema.csv`                          | 低-中    | SR 侧建表/校验 schema 兼容性（类型/默认值/表达式差异）      |
| business 表 TTL 元数据           | 从 `system.tables.engine_full` 提取 TTL 表达式与 TTL 数值                                                                                                                  | `business_ttl.csv`                          | 低       | 迁移后保持（或优化）数据保留策略，避免存储成本失控          |

## 五、后台任务与存储状态快照

| 采集内容/指标                             | 统计方式或公式（脚本口径）                                                                                                                | 导出位置（相对 `$OUTPUT_DIR` 或 JSON 字段） | 压力风险 | 在 CK -> SR 迁移中的作用                                                   |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | -------- | -------------------------------------------------------------------------- |
| parts/partitions 压力快照                 | `clusterAllReplicas(system.parts)`（限定 replica_num=1）按表聚合：`active_parts/uniqExact(partition)/sum(rows,bytes)/max(part_bytes)` | `snapshots/cluster_parts_snapshot.csv`      | 中       | 评估碎片度与合并风险；parts 过多通常意味着迁移时更容易抖动，需要更温和节奏 |
| merges 快照                               | `clusterAllReplicas(system.merges)` 按节点聚合：`count()/sum(num_parts)/sum(total_size_bytes_compressed)`                             | `snapshots/cluster_merges_snapshot.csv`     | 低-中    | 判断后台 merge 是否拥堵，迁移窗口尽量避开合并高压时段                      |
| mutations 快照                            | `clusterAllReplicas(system.mutations)` 过滤 `is_done=0` 按表聚合                                                                      | `snapshots/cluster_mutations_snapshot.csv`  | 低-中    | 识别未完成 mutation，避免迁移过程中数据状态不一致                          |
| ClickHouse 集群存储卷信息（system.disks） | `clusterAllReplicas(system.disks)` 输出 disk/path/total/free/keep_free_space                                                            | `snapshots/cluster_storage_volumes.csv`     | 低       | 了解现网存储卷布局与容量，为 SR 存储拓扑与容量预留提供依据                 |

## 六、流量与查询画像（最影响迁移体验与 SR 压测目标）

| 采集内容/指标                              | 统计方式或公式（脚本口径）                                                                                                                                                                     | 导出位置（相对 `$OUTPUT_DIR` 或 JSON 字段）          | 压力风险 | 在 CK -> SR 迁移中的作用                                             |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ | -------- | -------------------------------------------------------------------- |
| business 表写入行数分桶（逐表）            | 对 business-time-config 中每张表：`WHERE time_expr >= now()-N day`，按 `toStartOfInterval(time_expr, bucket)` 聚合 `count()`                                                             | `timeseries/business_table_writes/<db>/<table>.csv`  | 高       | 直接得到每表写入量的时序基线，决定 SR 写入容量/迁移切流窗口/限流策略 |
| query_log Insert 按表分桶（次数/写入行数） | `clusterAllReplicas(system.query_log)` + `ARRAY JOIN arrayEnumerate(databases)`，过滤 `QueryFinish/is_initial_query/query_kind=Insert`，按表+桶聚合 `count()` 与 `sum(written_rows)` | `timeseries/query_log_writes/`（目录内拆分为多文件） | 中-高    | 从请求侧刻画写入模式，校验业务表扫描结果，作为 SR 写入链路压测目标   |
| query_log Select 按表分桶（次数）          | 同上，过滤 `query_kind=Select`，按表+桶聚合 `count()`                                                                                                                                      | `timeseries/query_log_reads/`（目录内拆分为多文件）  | 中-高    | 读请求热点画像，指导 SR 索引/缓存/资源倾斜与迁移后体验基线           |
| query_log written_bytes 时序（含回退口径） | 优先聚合 `system.query_log.written_bytes`；否则回退 `system.part_log` NewPart；再回退 `system.parts` modification_time 近似                                                              | `timeseries/query_log_written_bytes_timeseries.csv`  | 中       | 写入带宽与落盘压力评估，为 SR 存储 IO 与写入吞吐规划提供量化输入     |
| query_log 延迟画像（p50/p95/p99/avg）      | `clusterAllReplicas(system.query_log)` 按 `query_kind+时间桶` 聚合 `quantile/avg/sum(read_bytes)/max(memory_usage)`                                                                      | `timeseries/query_log_latency_timeseries.csv`        | 高       | 迁移前体验基线，迁移后可直接对比 SR 的延迟是否退化/改善              |
| Top 慢查询（按 normalized_query 聚合）     | `GROUP BY normalized_query` 聚合 `count/p95/avg/sum(read_bytes)/max(memory_usage)`，按 p95 降序取 TopN                                                                                     | `slow_queries_top.csv`                               | 高       | 找到最该优先优化的查询模式                                           |
| 查询时间范围分布（按表，正则解析 SQL）     | 扫 `system.query_log`，对 `ql.query` 做多类正则解析估算范围天数，按表统计比例与分位；带 `SETTINGS max_threads/max_execution_time`                                                        | `query_time_range_distribution.csv`                  | 高       | 判断查询通常扫“近几天/近几月”                                      |

## 七、资源监控（来自 VictoriaMetrics）

| 采集内容/指标                      | 统计方式或公式（脚本口径）                                                                | 导出位置（相对 `$OUTPUT_DIR` 或 JSON 字段）     | 压力风险                | 在 CK -> SR 迁移中的作用                                          |
| ---------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------- | ----------------------- | ----------------------------------------------------------------- |
| CK Pod 资源时序（VM query_range）  | 多条 PromQL，按窗口计算 `avg_over_time/max_over_time`（CPU/内存/网络/磁盘 IO/Throttle） | `timeseries/ck_pod_usage_timeseries.prom`       | 低（对 CK）/中（对 VM） | 识别 CK Pod 侧资源瓶颈与峰值，为 SR 侧 Pod 配额与容量规划提供对照 |
| 集群节点资源时序（VM query_range） | 多条 PromQL，按窗口 `avg/max`（CPU/内存/磁盘/Swap/网络/IO/Load）                        | `timeseries/cluster_node_usage_timeseries.prom` | 低（对 CK）/中（对 VM） | 给出迁移窗口期的资源基线，帮助 SR 侧规划节点规格与迁移节奏        |
| 节点磁盘使用明细（VM 瞬时 query）  | `api/v1/query` 拉 `node_filesystem_size/free` 计算 used/used%                         | `snapshots/cluster_node_disk_usage.csv`         | 低（对 CK）/中（对 VM） | 用于容量水位评估，避免磁盘不足导致迁移失败                        |

# 废弃

* 如果ingest写数据没有明显的业务低峰概念，获取分时插入表的行数可以考虑去掉

# 确认要做的

- [ ] ck实例查询数、连接数、后台任务、缓存/内存水位等可以从vm中获取
- [X] 没获取真实节点上的磁盘剩余容量，而只是文件系统的，否则需要额外的ssh权限和账号（可以从vm获取，磁盘类型和raid无法获取，盘符），确认ck disks表 free的统计原理
- [X] 非系统db，逻辑/物化视图获取
- [X] 从vm的ingest获取打点，按表级别，干掉ck的按表级别查询
- [ ] 区分人查，机查的query，默认7天
- [ ] 指标对于升级场景的作用说明

# 待确认的

- [X] 确认下arm环境,比如avx指令，starrocks所依赖的指令集
- [ ] vm查也可能超时，it部门先确认
- [ ] 统计分区大小可能统计不出来
