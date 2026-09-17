# diting 设备维护笔记

适用：`android_kernel_xiaomi_diting`（小米 K50 至尊版 / diting，GKI android12-5.10）

## 一、上游合并的规矩

1. **以上游为准**：内容以 kernel.org 上游（`v5.10.x` tag）为准。
   第三方 GKI 树（`ramabondanp/android_kernel_common-5.10` 的 `android12-5.10-staging`）
   里的 `Revert` 提交，视作"该维护者的改动"，逐条审视，**不默认采信**。
2. **有风险的改动单独一个提交**，便于真机测试后一键 `git revert`。
3. **上真机前先拿日志**：`/sys/fs/pstore/console-ramoops-0`
   （本树已开 `CONFIG_PSTORE=y` / `CONFIG_PSTORE_CONSOLE=y` / `CONFIG_PSTORE_RAM=y`，
   重启到能开机的系统后用 root 文件管理器或 recovery 读取即可，无需 adb）。

## 二、记录：remoteproc / of / irqchip-mbigen 的上游改动为什么不恢复

### 背景
合并 5.10.270 用的是第三方 `android12-5.10-staging`（`f4726c12d35e`），
它在 270 之后撤掉了 18 个上游提交。我们把其中安全/bug 类逐个恢复。

### 已恢复，且真机验证可正常开机（commit `2d5a6e073ac3`）
- netfilter: nf_queue 持有 fake dst 时 pin 住 bridge device（UAF）
- USB: serial: keyspan_pda 修复信息泄露
- tcp: 修复 `tcp_v6_syn_recv_sock()` 竞态
- espintcp: 去掉 encap socket caching，避免引用泄漏
- HID: 及时释放驱动分配的资源
- media: v4l2-dev: `__video_register_device()` 错误处理
- power: supply: sc2731_charger: cancel work on remove / 平台 remove 回调

### 试过，但必须撤回（commit `26dcc45a58b8`，已由 `17c272a3792c` 撤回）
- remoteproc: RPROC_ATTACHED 状态、异步 attach、`rproc_detach()`、`__rproc_detach()`、
  `detach()` 操作、crash handling 与 `rproc_del()` 的竞态
- of: property: `of_graph_get_endpoint_count()` 返回 `unsigned int`
- irqchip/mbigen: mbigen node 地址布局

### 真机复现
刷入后**卡在开机动画不动**（内核已起来、动画在转，但系统进不去）。

### 估计原因
这批改动动的是 **remoteproc 的核心生命周期**（attach/detach 状态机、`rproc_del()` 路径）。
diting 的 **adsp/cdsp 就跑在 remoteproc 上**，生命周期被改后 DSP 起不来，依赖 DSP 的服务
（音频等）在开机阶段一直等不到 → 表现为卡开机动画。

`of` / `mbigen` 两项与 remoteproc 无关，只是随同一提交一起撤回：`irqchip/mbigen` 是
HiSilicon 的中断控制器、**不在 diting 上**，`of: property` 仅是返回类型的小修，
单独恢复价值极低，故不再单独补。

### 取舍
- **放弃**：remoteproc 那 6 个上游改动（含 `crash handling 与 rproc_del()` 竞态的潜在
  UAF 修复）。该修复很可能依赖那套 detach/attach 重构、单独打并不成立；
  对真机而言**"能开机"优先**。
- **保留**：final 5.10.270 的全部内容 + 上面 8 个安全/bug 修复。

### 教训
`remoteproc` / 平台驱动 API / DT 布局 这三类上游改动，**若第三方撤过，默认先不恢复**
（容易和厂商 blobs / DSP / DTB 打架）；确实要恢复也必须单独提交 + 真机验证。

## 三、运行时 A/B 与调试（不用重新编译）

### IO 调度器切换
默认调度器被钉在 `block/elevator.c` 的 `elevator_get_default()`（当前 `ssg`），
但运行时可以随时换，不需要重新出包：

    for d in /sys/block/sd*; do echo mq-deadline > $d/queue/scheduler; done

可选：`none` / `mq-deadline` / `kyber` / `bfq` / `ssg` / `adios`。

`adios`（Adaptive Deadline I/O scheduler）在 `block/Kconfig.iosched` 里是
`tristate` + `default m` —— **默认就编成模块**，用之前先 `modprobe adios`。

### DAMON_RECLAIM 做 A/B
实验分支（`exp`）里默认开着，运行时可随时开关对比：

    echo 0 > /sys/module/damon_reclaim/parameters/enabled
    echo 1 > /sys/module/damon_reclaim/parameters/enabled

### 两个容易看错的点
- `BLK_WBT` 开着也可能**空转**：看 `/sys/block/*/queue/wbt_lat_usec`，为 `0` 就是没在限流。
- 配置项的**默认值**也算数：defconfig 里没写的项按 Kconfig 的 `default` 生效
  （ADIOS 就是这样一直出模块的；改成 `=y` 反而会常驻内存）。

## 四、zram 算法矩阵，以及"重压缩"为什么搬不进来

### 当前可用的压缩后端（都已编译进去，可运行时切换）

    cat  /sys/block/zram0/comp_algorithm          # 列出可用算法，当前项带 []
    echo zstd > /sys/block/zram0/comp_algorithm   # 换算法（需设备未初始化/reset 后）

lz4 / lz4hc / lzo / lzo-rle / zstd / deflate / 842，
外加本树移植的三个厂商算法 **lz4k / lz4kd / lz4k_oplus**。
默认是 `CONFIG_ZRAM_DEF_COMP="lz4"`。

### 上游的 recompression（多算法共存）为什么搬不进来

上游自 6.6 起有 recompression（即后来的 `ZRAM_MULTI_COMP`：`recomp_algorithm` +
按优先级用二级算法再压冷页）。**它无法直接移植到本树**：

1. 那套代码建立在 zram 的 **blk-mq 化**之上（6.6 用 `blk_alloc_disk()`、
   `zram_bio_read/write()`、`zram_read_from_zspool()` 等），而本树是 **bio-based**
   （`alloc_disk(1)`）——整文件移植等于连 blk-mq 化一起搬，I/O 路径和 ssg 调度器都会变 ✗
2. 它还依赖 zsmalloc 的 **zspage class API**（`zs_lookup_class_index()`，5.15+），
   本树 5.10 的 zsmalloc 没有 ✗
3. 需要的 block API 本树也缺：`blk_alloc_disk` / `memcpy_{from,to}_bvec` /
   `bio_advance_iter_single` / `set_capacity_and_notify` ✗

### 可行的替代（自实现精简版）

在本树 bio-based zram 上自己做一个：加一个二级 `struct zcomp`（`recomp_algorithm` 可写），
在回收 worker 里对 **IDLE 且压缩后仍偏大**的页执行"读回 → 二级算法再压 → 明显更小才换
handle"，用 `comp_len` 比较替代 `zs_lookup_class_index()`。配置开关默认关闭，
整颗可以用 `git revert` 撤掉。
