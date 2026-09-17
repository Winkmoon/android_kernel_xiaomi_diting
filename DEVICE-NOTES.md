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

## 五、Android 17 与 5.10：官方要求、启动时那个"版本号"、以及本树实测差距

### 1. 官方事实（source.android.com → Android common kernels）

- Android 17(2026) 的支持列表里**仍然列着** android12-5.10 与 android13-5.10，
  但标注 **"not supported in Android 17 QPR1 or higher"** —— 是**从 QPR1 起**才移除。
- `android12-5.10` 的 **EOL = 2027-07-01**（6 年支持期），之后不再有安全补丁。
- **KMI 不跨 GKI 保持兼容**（官方原话：android14-6.1 内核不能直接换 android15-6.6，
  必须重编全部模块）→ 想换 6.x 内核对这台机器不可行。
- Android 17 起 **ION 分配器不再支持**；本树 `# CONFIG_ION is not set` ✓ 不受影响。
- 官方机制：**KMI 冻结后只允许"新增"导出符号**，不动已有接口就不破坏兼容
  → 所以"加法式"的 backport 才是安全的。

### 2. 启动时读到的"版本号"到底是什么（这就是听说要"动手脚"的地方）

三个层次，千万别混：

| 名字 | 位置 | 作用 | 能不能动 |
|---|---|---|---|
| **KMI generation** | `build.config.common: KMI_GENERATION=9`（本树就是 9） | 决定 `uname` 串里的 `-android12-9-` | 动它 ⇒ **厂商模块直接不兼容**（官方原话）✗ |
| **`CONFIG_LOCALVERSION`** | defconfig：本树 `"-Xinran_StarBai-Stars"` | 拼进 `uname -r`，**也拼进每个模块的 vermagic** | 改它必须**内核与模块同一次构建**一起刷（现在就是这么做的 ✓） |
| **`CONFIG_MODULE_SCMVERSION`** | `init/Kconfig:2262`，本树有但没开 | 给模块加一个**可查询属性**（`modinfo -F scmversion` / `/sys/module/*/scmversion`）；实现是 `MODINFO_ATTR(scmversion)`，**不进 vermagic，不影响模块加载** | 官方 GKI 开着；本树**想开也开不了**（它 `depends on LOCALVERSION_AUTO`，而本树故意 `LOCALVERSION_AUTO=n`）|
| **`CONFIG_LOCALVERSION_AUTO`** | 本树**有意设为 n** | 关掉它 ⇒ vermagic **不含 git hash** | ✅ **保持现关**：这样不同提交编出来的模块仍能互相加载（自用内核的正确取舍）|

**结论：不要伪造版本号。** 假装成 6.x 不会让缺的功能出现，反而立刻破坏模块加载
（vermagic 不匹配 ⇒ 开不了机）。真正决定"能不能开机"的是三条：
**① 内核与模块来自同一次构建；② 导出符号/KMI 没被破坏；③ 平台镜像需要的内核特性齐备。**

活的参照物：本机这颗内核 `5.10.236-android12-9-o-g7b827c1e7f33` 就是一颗真 ACK/GKI，
`uname -r` 里的 `android12-9` 正是"平台版本 + KMI generation"。

### 3. 与 Android 17 官方 GKI（android17-6.18）的实测差距

- **系统调用**：相对 android17-6.18 的官方 GKI，本树缺 26 个
  （442–462 区间的 20 个 + `file_getattr`/`file_setattr` 与 `*xattrat` 家族等）。
  **全部返回 ENOSYS**：arm64 的 syscall 表被 `[0 ... __NR_syscalls-1] = __arm64_sys_ni_syscall`
  整表预填（`arch/arm64/kernel/sys.c:59`），**不会崩**；而 Android 的 userspace
  对这些调用**都写了 fallback** ⇒ **不构成开机障碍**。
  - 已补：**`fchmodat2`（452）** —— bionic 的 `fchmodat(AT_SYMLINK_NOFOLLOW)` 没有可用替代路径。
  - 未补（有 fallback 且实现很大）：`mseal`、`mount_setattr`、`landlock_*`、`futex_waitv` 等。
- **配置**：逐项对比 android17-6.18 的 `gki_defconfig`，本树补齐了 11 项
  （cgroup 控制器 `CGROUP_PIDS`/`CFS_BANDWIDTH`/`NET_CLS_CGROUP`/`BLK_DEV_THROTTLING`，
  netfilter `XT_MATCH_CONNBYTES`/`IP_NF_MATCH_RPFILTER`/`NF_CONNTRACK_PROCFS`，
  IPv6 `MULTIPLE_TABLES`/`MROUTE`/`MROUTE_MULTIPLE_TABLES`/`SUBTREES`）。
  - 故意**不**补：`ANON_VMA_NAME`/`BPF_LSM`/`MSEAL_SYSTEM_MAPPINGS`（本树没有对应代码）、
    `LRU_GEN`（MGLRU，在 5.10 上是 **KMI-breaking**，AOSP 自己都放在 brokenkmi 分支）。
- **启动关键项复核**（与本机那颗真 GKI 内核逐项对照）：EROFS(+ZIP) ✓、
  fscrypt/inline-crypt ✓、dm-verity/dm-default-key ✓、binderfs ✓、incfs ✓、
  PSI/MEMCG/MEMCG_SWAP ✓、ashmem ✓、dma-heap ✓、4K 页 ✓ —— **一致**。
  - `EROFS_FS_ZIP_LZMA/ZSTD` 本树没有，**Google 的 android12-5.10 GKI 也没有** ⇒
    ROM 的镜像不会用（16.18 的 GKI 才有 ZSTD），无需处理。
  - `ENCRYPTED_KEYS` 本机 GKI 同样 not set ⇒ 不动。
  - 16KB 页：本 SoC 是 4K（`ARM64_4K_PAGES=y`），Android 16+ 只对新机型要求 16K ⇒ 无关。
- **KMI 安全审计**：`exp` 分支全部提交**没有删除任何 `EXPORT_SYMBOL`**、没碰
  `android/abi_gki_aarch64*`、只**新增**了系统调用号（不重编号）⇒ 对厂商模块安全。

### 4. 想让"新 Android + 这台机器"跑起来，正确路线

1. **最稳**：用目标 ROM 自带的那颗 5.10 内核（社区已为"新 Android + 这台机器"验证过），
   把自己的定制重打上去。
2. 要用自己的树：把 **AOSP ACK**（`https://android.googlesource.com/kernel/common`，
   分支如 `android12-5.10` / `android17-6.18`）当**权威参照**，直接对比缺什么，
   比照 6.18 猜准得多。
3. **权威的"要求清单"在 ROM 里，不在内核里**：解包 ROM 看
   `*/etc/vintf/manifest.xml` 与 `*/etc/vintf/compatibility_matrix.*.xml` ——
   后者里 `<kernel version="X.Y.Z"/>` 和 `<kernel config="CONFIG_..."/>`
   就是平台对**内核版本 + 必需配置**的正式要求。
4. **真正的风险不在内核版本**，而在 **vendor 分区/闭源 HAL 仍是 Android 12 时代的**
   （VNDK/VINTF 不匹配）。

### 5. 怎么快速拿到 ACK 的配置来对比（省流量版）

    git clone --filter=blob:none --no-checkout --depth 1 -b android17-6.18 \
        https://android.googlesource.com/kernel/common ack
    cd ack && git sparse-checkout set arch/arm64/configs include/uapi/asm-generic
    git checkout      # 只取这几个目录，约 15 MB

### 6. 和 **官方同版本线**（android12-5.10 ACK）的对比 —— 最权威的一步

拉官方的 `android12-5.10`（`https://android.googlesource.com/kernel/common`，2026-08 的
tip，`KMI_GENERATION=9` ✓ 与本树一致）逐项比：

| 对比项 | 结果 |
|---|---|
| 系统调用集合 | **完全一致** —— 官方 5.10 线同样**没有** `fchmodat2`/`mseal`/`mount_setattr`/`futex_waitv` 等 ✓✓ ⇒ "这些缺失不影响 Android 17 跑在 5.10 上"**得到官方背书** |
| `__NR_syscalls` | 官方 **449**；本树 **453**（我加了 `fchmodat2`=452，**超出官方线**，无害但要知情） |
| 平台相关配置缺口 | 只剩 3 项：`MODULE_SCMVERSION`（见上，不能开也不必要）、`IKHEADERS`（BPF 工具用，会让镜像大几 MB，**不加**）、`ARM64_SW_TTBR0_PAN`（加固项，非开机必需，**不加**） |

**结论：内核侧你这条线已经和官方 5.10 一致了** ✓ —— 缺的那点东西官方也缺 ✓。
所以"Android 17 能不能跑"的瓶颈**不在内核**，而在 **vendor 分区 / 闭源 HAL 的版本**（VNDK/VINTF）。

### 7. 两小时里改了什么（`exp` 分支）

- `fchmodat2`（新增系统调用 452）—— 唯一一处**超出官方 5.10 线**的加法
- 11 个配置项（cgroup 控制器 / netfilter / IPv6 组播），依据是 android17-6.18 的官方 gki_defconfig
- 本说明文档
- **未改**（刻意）：`CONFIG_LOCALVERSION`、`LOCALVERSION_AUTO`、`MODULE_SCMVERSION`、
  以及任何需要大改代码的东西（`mseal`/`landlock`/MGLRU/`ANON_VMA_NAME`）

## 六、Android 各版本对内核的正式要求（一手来源）与合规核对

### 要求清单在哪

AOSP 仓库 **`kernel/configs`**（`https://android.googlesource.com/kernel/configs`）：

- 顶层目录按 Android 大版本代号：`r/`=11、`s/`=12、`t/`=13、`u/`=14、`v/`=15、
  `b/`=16、`c/`=17，另有 `d/`（更新的一档）。
- 每级下面按内核线分目录 `android-<版本>/`，里面有：
  - **`android-base.config`** —— 该内核线的**必备配置**，含"必须关闭"的负向项
  - **`android-base-conditional.xml`** —— **条件要求**（按架构/内核版本；头部
    `<kernel minlts="5.10.107" />` 就是这条线的最低 LTS）
- **`kernel-lifetimes.xml`** —— 每条线的 launch / EOL（`android12-5.10` 的 **EOL = 2027-07-01**）

### 各 Android 版本定义了哪些内核要求集（android17-release 分支实测）

| Android 版本 | 要求集 |
|---|---|
| 13（`t/`） | `android-5.10` + `android-5.15` ← **5.10 的最后一份** |
| 14（`u/`） | `android-5.15` + `android-6.1` |
| 15（`v/`） | `android-6.6` |
| 16（`b/`） | `android-6.12` |
| 17（`c/`） | **`android-6.18`（只有它）** |

**⇒ "Android 17 QPR1 起不支持 5.10"的具体含义 = 官方不再为 5.10 定义要求集**
（因而也不再对它做兼容性测试）。它**不是运行时的拒绝** —— ROM 能不能在 5.10 上跑，
取决于该 ROM 自己的 vendor 侧与 FCM；QPR 只是给"官方承诺"画上句号。

### 本树的合规核对（用 `t/android-5.10` 那份最终要求集逐项查）

- **正向要求 253 项：缺失 0** ✓
- **负向要求（必须关闭）：违规 0** ✓
- ⇒ **本树内核配置与官方对 5.10 的最终要求 100% 一致**

核对中查出并修正的两处偏差（都来自之前那个 "restore the GKI switches" 提交）：

| 项 | 官方要求 | 原厂 defconfig | 曾改成 | 现在 |
|---|---|---|---|---|
| `CONFIG_SYSVIPC` | 关闭 | 关闭 | 开 ✗ | 关闭 ✓ |
| `CONFIG_IP6_NF_NAT`（连带 `_TARGET_MASQUERADE`） | 关闭 | 关闭 | 开 ✗ | 关闭 ✓ |

**教训（重要）**："原厂没开"或"第三方 GKI 开了"**都不能当依据**；
权威依据只有 `kernel/configs` 里那份要求集。
