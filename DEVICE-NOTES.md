# diting 设备维护笔记

适用：`android_kernel_xiaomi_diting`（红米 K50 至尊版 / diting，GKI android12-5.10）

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
