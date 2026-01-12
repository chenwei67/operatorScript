# operatorScript

# todo

我现在的架构是：ck运行在k8s上，数据存储在挂载了pvc的目录上，pvc是本地存储，大概率使用local-path-provisioner来制备pv。当前部署了node_expoter和cadvisor。

我的需求是搜集关于ck的一些指标，希望了解其数据目录的文件系统容量使用趋势，有办法获取吗？
