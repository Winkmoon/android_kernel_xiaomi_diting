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

## 十、怎么快速查"上游有没有新东西"，以及怎么安全地只挑修复

### 1) 查最新版本（秒回，不会卡）

```
curl -sS https://www.kernel.org/releases.json | jq -r '.releases[] | select(.version|startswith("5.10"))'
```

⚠️ **不要**用 `git ls-remote <stable 仓库> 'v5.10.*'` 去列 tag —— 那仓库几千个 tag，走 HTTP 会卡死超时。

### 2) 查 AOSP ACK 官方分支的新提交（gitiles 小接口，秒回）

```
curl -sS "https://android.googlesource.com/kernel/common/+log/refs/heads/android12-5.10?format=JSON&n=100" | tail -c +6 | jq -r '.log[] | "\(.commit[0:12]) \(.committer.time) \(.message|split("\n")[0])"'
```

再把每个 sha 用 `git cat-file -e <sha>^{commit}` 对本地查一遍：**本地没有的 = 你缺的**。

### 3) 取单个提交的补丁并判断"是不是已经合过了"

```
curl -sS "https://android.googlesource.com/kernel/common/+/<sha>%5E%21/?format=TEXT" | base64 -d > p.patch
git apply --check --reverse p.patch   # 成功 ⇒ 内容已在树里（可能是别的提交带进来的）⇒ 直接跳过
```

gitiles 返回的是**纯 diff、没有邮件头**，所以 `git am` 不认（`Patch format detection failed`）——
要么手工 `git apply` + 自己建提交（保留原作者/日期 ✓），要么老老实实 fetch 整个分支。

### 4) 冲突了怎么办：看"这个补丁真正在做什么"

例：f2fs compress 那个 UAF 补丁在 zstd 那几行冲突，因为你树还是**旧的 lowercase zstd API**
（`zstd_init_dstream`/`zstd_is_error`），而 ACK 已转成 `ZSTD_initDStream`/`ZSTD_isError`。
那几行和补丁的**目的无关** ⇒ 冲突全取 ours，然后只做它真正的替换
（`F2FS_I_SB(dic->inode)` → `dic->sbi`）✓。

**教训：冲突不等于"不能合"，要先看清补丁的意图，再决定每处取哪边。**

## 十一、记录：双击亮屏要按好几下（已 revert 一个第三方 backport）

### 背景
升级到 5.10.270 之后，真机上**双击亮屏要点好几下才亮**，而**双击熄屏正常**。
日志（`22222.txt`，dmesg 644s～698s）里能看到手势事件确实上报了：
`[TP-Driver] [ FTS ] fts_gesture_event_handler: double tap !`，
随后是 DRM notifier → `System resetting...` → `fts_mode_handler: Screen ON...` 这条 resume 路径。

### 根因
第三方（`Ramanarubp`，2026-09-14 提交、作者 Rafael J. Wysocki）backport 的
`18efabd8122e "BACKPORT: PM: sleep: Do not flag runtime PM workqueue as freezable"`
把 `__device_suspend_late()` 里的 `__pm_runtime_disable(dev, false)`
换成了 **`pm_runtime_disable(dev)`**。

后者会置位 `disable_depth`：**在 `device_resume_early()` 里配对 `pm_runtime_enable()`
之前，该设备的任何 runtime PM 调用都会失败**（补丁自己加的注释就是这么写的）。

FTS 触摸驱动是**厂商模块**（本树里没有 `fts_*`，日志里的 `[TP-Driver]` 也搜不到 ⇒
它来自 vendor 分区），它的手势唤醒路径要在中断里对触摸设备做 runtime PM resume。
**第一次双击正好落在这个窗口内 ⇒ resume 失败 ⇒ 屏幕不亮**，
多点几下等系统 resume 走完才成功 —— 与报告的现象完全一致。

### 取舍
整条 revert（它另外还各改了 `Documentation/power/runtime_pm.rst` 和
`kernel/power/main.c` 一处），**单开一个提交**便于单独撤回：

- revert 后双击恢复正常 ⇒ 保留；
- 若无效 ⇒ `git revert` 掉这个 revert，再往别处查（下一个怀疑对象：
  `drivers/base/platform.c` 的 422 行改动、`kernel/irq/irqdomain.c`）。

### 顺带记录（同一次排查里排除掉的）
- `xm_power: active wake lock: a600000.ssusb, active_since: 521041ms` ——
  看着吓人，但 `drivers/usb/mtu3/mtu3_dr.c` 那段 `pm_stay_awake()` **是上游自己的**
  （`d0ed062a8b75 "usb: mtu3: dual-role mode support"`，注释写着
  "avoid suspend when works as device"），本树与上游 5.10.270 **零差异** ⇒ 不是 bug。
- 日志里的 `cnss/qca6490`、`xm_power`、`mi_disp`、`healthd`、
  `(virq:irq_count)` 统计行等，全部来自**厂商模块**，不在 GKI 树内。

### 补记：同一系列的另一个 backport 也 revert 了
`039ad7273fd8 "BACKPORT: PM: WQ_UNBOUND added to pm_wq workqueue"`（Marco Crivellari 作者、
同一个第三方 `Ramanarubp` 2026-09-14 提交、和前一个是**同一天同一批**）给 `pm_wq` 加了
`WQ_UNBOUND` —— 让 runtime PM 的 work 不再固定在本地 CPU。它只是**调度位置**的改动，
在手机上没有收益，但会**改变唤醒时序**，而双击亮屏正是依赖唤醒时序的那条路。
单独一个 revert 提交（`Revert "BACKPORT: PM: WQ_UNBOUND added to pm_wq workqueue"`），
可独立撤回。

### 顺带审了一遍「非上游来源」的提交
`14413bbb3f24..HEAD` 里有 **194 个** 带 `BACKPORT:` / `FROMLIST:` / `ANDROID:` 标记的提交，
提交者统计：`Greg Kroah-Hartman 5579`、`Rama Bondan Prakoso 533`（第三方）、`Sasha Levin 334` …
其中**设备相关、值得盯**的两处：

1. **PM 系列**（已处理）：`18efabd8122e` + `039ad7273fd8` 两个，已各开一个 revert。
2. **mm 的 per-cpu page 远端回收**（未动，列为观察项）：
   `f6272832be16 FROMLIST: BACKPORT: mm/page_alloc: Remotely drain per-cpu lists`、
   `310077eb8ccb FROMLIST: BACKPORT: mm: fix is_pinnable_page against on cma page`、
   `b05425fb1467` / `78e708427e8f ANDROID: fix ABI breakage caused by ...`
   —— 这是从更新内核带过来的**性能特性**（不是修复），动它会改变内存回收时序；
   目前没有真机症状指向它，所以**没动**。若之后再出现"偶发卡顿/回收相关"的怪现象，
   优先怀疑这一组。

其余 `Revert "..."` 类提交（remoteproc / sc2731 / keyspan / v4l2 / HID / netfilter 等）
是第三方自己的取舍，本笔记第二节已记录过其中 remoteproc 那一批（试过、卡开机、已撤回）。

### 更正：上一节的结论被真机推翻（已恢复那两个 backport）

**真机实测结果**：把 `18efabd8122e` 和 `039ad7273fd8` 两个 backport revert 掉之后，
双击亮屏从「按几下才亮」变成**完全不响应，只能用电源键**。

⇒ 说明这两个 backport 在**帮忙** ✓ 而不是在捣乱 ✗ ⇒ 上一节的假设**不成立** ✓，
已把两个 revert 各自撤回（`Revert "Revert ..."`），代码逐字恢复到原样 ✓。

**为什么方向搞反了**：这两个补丁的作用恰恰是**让 async runtime resume 在系统 PM 转换
期间仍然可用**（`18efabd8122e` 的正文写得很明确）✓，而 FTS 触摸驱动是**厂商模块** ✓，
它的手势唤醒路径就是在中断里请求一次 runtime resume ✓ —— 正好落在"系统还在
suspend/resume 转换中"这个窗口 ✓ ⇒ 把这条路径拿掉，手势唤醒**直接失效** ✓。

**教训**：这次是"看着代码注释就下结论" ✗ —— 注释说的"驱动在这里做的 runtime PM 会失败"
我拿来当作"所以它挡了触摸" ✓，但真正要问的是**触摸驱动到底需不需要在这个窗口里
成功做一次 runtime resume** ✓ —— 实测给了答案：需要 ✓。以后这类时序问题，
先要真机日志，再动代码 ✓。

**下一步（不再靠猜）**：需要一次失败尝试时的 dmesg，关键只看一件事 ——
`fts_gesture_event_handler: double tap !` 是**每次双击都出现** ✓，
还是**只有最后成功那次才出现** ✗：

- **每次都有** ⇒ 触摸芯片认了手势 ✓，是**唤醒/恢复路径**没走通 ⇒ 继续看 PM/DRM notifier 时序 ✓
- **只有成功那次才有** ⇒ 芯片/中断根本没被正确 armed ⇒ 方向完全另一条（中断唤醒 + 面板 notifier 顺序）✓

其它一并要看（都在同一份日志里就能区分）：
- `fts_palm_sensor_cmd 1` / `palm_sensor_store value:1` 在 resume 后立刻出现 ✓
  —— MIUI 的**防误触**可能在吞掉最初几下 ✓（这是用户态参数，内核侧改不了 ✓）
- 悬浮/口袋模式、以及设置里"双击亮屏"相关的 MIUI 配置 ✓

**注意**：触摸驱动是**厂商模块**（不在本仓库 ✓），手势的门限/时序参数来自 MIUI 配置 ✓
⇒ 如果最后确认是模块或配置问题，内核侧可能根本没有可改的地方 ✓，别硬改 ✓。

### 补充：失败场景其实是"插着线"，不是"睡着"（原假设第二次被真机推翻）

真机实测（用户）：**拔掉充电器 = 双击正常** ✓；**插上充电器 = 双击没反应/要按好几下** ✗。
⇒ 我上一条"病在睡着之后那条路"的推断**作废** ✗ —— 恰好相反 ✓。

**日志证据（两份都支持"充电噪声抑制"这个特性解释）**：
- 两份日志（`22222.txt` / `23333.txt`）都发生在**插着线**的时候 ✓：`chg_type=SDP` ✓、
  `a600000.ssusb` 唤醒锁分别持有 562s / 373s ✓、`adsp_sleepmon ... suspend_event = 0` ✓、
  `PM: suspend` 出现 **0** 次 ✓ ⇒ 全程**没有进 suspend** ✓；
- 而这两份日志里**各自都有 2 次双击成功** ✓ ⇒ 所以不是"充电就禁用" ✗，
  而是"**充电时被抑制/变迟钝**" ✓ —— 正好对应"要按好几下才亮" ✓；
- 每次唤醒都跟着一条 `fts_write_charge_status charging_status:2` ✓ ——
  **触摸驱动把充电状态写进触摸芯片** ✓✓ ⇒ 芯片据此改变手势检测策略（抗充电器噪声的常规做法）✓；
- GKI 侧 `xiaomi_touch` 另外还暴露了 `touch_thp_noisefilter`（噪声滤波）✓、`palm_sensor` ✓，
  同样指向"充电噪声"这条线 ✓。

**结论**：优先按"厂商特性"处理 ✓ —— 拔线正常、插线迟钝 ✓，不是内核 bug ✓。

**还需一份日志才能彻底钉死**（区分"芯片没认"和"认了没醒"）：
插着线做一次**失败**尝试（没亮），立刻 `dmesg | grep -aE "double tap|fts_" | tail -30`：
- **没有** `double tap !` ⇒ 芯片没认手势 ⇒ **特性** ⇒ 内核无杠杆 ✓（只能走设置/固件/ROM ✓）
- **有** `double tap !` 但没亮 ⇒ 才可能是内核侧 ✓

**我这边**：既然失败场景根本不进 suspend ✓，上一节加的 `CONFIG_PM_DEBUG=y` 已经没用 ✗ ⇒ 已撤回 ✓，
保持树干净 ✓；哪天真的需要查 suspend 再加 ✓。
