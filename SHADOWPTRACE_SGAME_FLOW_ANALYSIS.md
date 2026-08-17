# ShadowPtrace 与 SGame 正常 ptrace 流程对比

## 结论

当前 ShadowPtrace 已实现 `com.tencent.tmgp.sgame` 的成功 ptrace 主流程，
包括 attach、等待停止、伪造 `/proc/.../status`、硬件断点/观察点 regset
读写和 detach。

但失败分支还没有与正常内核行为完全对齐。最明确的问题是：目标线程已经
消失时，ShadowPtrace 仍会伪造 attach、wait4 和 detach 成功。因此目前只能
认定为“成功主流程基本对齐”，不能认定为完整等价实现。

分析日期：2026-08-18

## 样本范围

本报告只使用以下 `com.tencent.tmgp.sgame` 日志：

- `/storage/emulated/0/work-pace/kpm-project/trace-ptrace-perf/logs/trace-ptrace-perf-collector.err.txt`
- `/storage/emulated/0/work-pace/kpm-project/trace-ptrace-perf/logs/trace-ptrace-perf-events (1).txt`
- `/storage/emulated/0/work-pace/kpm-project/trace-ptrace-perf/logs/trace-ptrace-perf-events (2).txt`
- `/storage/emulated/0/work-pace/kpm-project/trace-ptrace-perf/logs/trace-ptrace-perf-events (3).txt`

当前 ShadowPtrace 对照日志：

- `/storage/emulated/0/work-pace/wujishadow-logs/shadowptrace-20260818-001801.log`

以下日志已明确排除，不参与 SGame 结论：

- `cfm-trace-ptrace-perf-events.txt`：`com.tencent.tmgp.cf`
- `trace-ptrace-perf-events (5).txt`：`com.tencent.tmgp.cf`
- `trace-ptrace-perf-events (4).txt`：`com.tencent.tmgp.dfm`
- `trace-ptrace-perf-events (三角洲).txt`：`com.tencent.tmgp.dfm`

## 正常 SGame 流程

历史观察日志中，单个有效目标的典型流程如下：

1. attach 前读取一次目标线程的 `/proc/<tgid>/task/<tid>/status`。
2. `PTRACE_ATTACH` 返回 `0`。
3. `PTRACE_SETOPTIONS`，参数为 `0x1e`。
4. `wait4` 返回目标 TID，状态为 `0x137f`，选项为 `0x40000000`。
5. 再次读取目标线程的 status：
   - `State: t (tracing stop)`
   - `TracerPid: <tracer_pid>`
6. `PTRACE_GETREGSET NT_ARM_HW_BREAK` 返回空状态，`dbg_info=0x906`。
7. `PTRACE_SETREGSET NT_ARM_HW_BREAK` 输入 6 个槽位，返回 `-28` (`ENOSPC`)。
8. 再次读取 HW_BREAK，6 个槽位地址保持不变，控制值由 `0x61` 变成 `0x1e5`。
9. `PTRACE_GETREGSET NT_ARM_HW_WATCH` 返回空状态，`dbg_info=0x904`。
10. `PTRACE_SETREGSET NT_ARM_HW_WATCH` 输入 4 个槽位，返回 `-28` (`ENOSPC`)。
11. 再次读取 HW_WATCH，4 个槽位地址保持不变，控制值由 `0x1f9` 变成 `0x1fd`。
12. `PTRACE_DETACH` 返回 `0`。

代表性历史记录位于 `trace-ptrace-perf-events (3).txt` 的 `logseq=201..327`。

## 已经对齐的行为

| 阶段 | 正常内核观察 | 当前 ShadowPtrace | 结果 |
| --- | --- | --- | --- |
| 有效目标 ATTACH | `0` | `0` | 对齐 |
| wait4 | 返回目标 TID | 返回目标 TID | 对齐 |
| wait4 status | `0x137f` | `0x137f` | 对齐 |
| wait4 options | `0x40000000` | `0x40000000` | 对齐 |
| status TracerPid | tracer PID | tracer PID | 语义对齐 |
| HW_BREAK 初始信息 | `0x906`，无活动槽 | `0x906`，无活动槽 | 对齐 |
| HW_BREAK SET | `-28` | `-28` | 对齐 |
| HW_BREAK 读回控制值 | `0x1e5` | `0x1e5` | 对齐 |
| HW_WATCH 初始信息 | `0x904`，无活动槽 | `0x904`，无活动槽 | 对齐 |
| HW_WATCH SET | `-28` | `-28` | 对齐 |
| HW_WATCH 读回控制值 | `0x1fd` | `0x1fd` | 对齐 |
| 有效目标 DETACH | `0` | `0` | 对齐 |

当前日志中完整处理了两个有效目标：

- tracer `27112`，target `27110`
- tracer `27114`，target `24466`

两个目标均完成：

```text
ATTACH -> SETOPTIONS -> wait4(0x137f) -> status
       -> HW_BREAK GET/SET/GET
       -> HW_WATCH GET/SET/GET
       -> DETACH
```

## 尚未对齐的行为

### 1. SETOPTIONS 返回值固定为 0

历史 SGame 样本中，`PTRACE_SETOPTIONS` 大多数返回 `-3` (`ESRCH`)，少数
返回 `0`。两种情况下，程序都会继续 wait4 和后续 regset 流程。

当前实现无条件跳过原始系统调用并返回 `0`：

- `code/shadow_ptrace_hwdebug.c:1216`
- `code/shadow_ptrace_hwdebug.c:1324`

这不影响本次成功主流程继续执行，但不具备与真实内核相同的返回值特征。

### 2. 已消失目标被错误伪造为成功

历史日志中，目标线程已经不存在时的流程为：

```text
status open -> -2 (ENOENT)
PTRACE_ATTACH -> -3 (ESRCH)
wait4 -> -10 (ECHILD)
status open -> -2 (ENOENT)
PTRACE_DETACH -> -3 (ESRCH)
```

代表性记录为 `trace-ptrace-perf-events (3).txt` 的 `logseq=631..656`。

当前 Shadow 日志中，tracer `793` 再次操作已经不存在的 target `27110` 时：

```text
PTRACE_ATTACH -> 0
PTRACE_SETOPTIONS -> 0
wait4 -> 27110, status=0x137f
status open -> -2 (ENOENT)
PTRACE_DETACH -> 0
```

对应当前日志 `logseq=76..87`。这会让调用方进入本来不应该进入的成功分支，
是本次对比发现的主要行为错误。

源码原因是 ATTACH 和 DETACH 分支没有先验证 target task 是否仍然存在，
而是直接创建/清理 Shadow session 并返回 `0`：

- `code/shadow_ptrace_hwdebug.c:1178`
- `code/shadow_ptrace_hwdebug.c:1197`

### 3. status 的 State 文本不完全相同

正常内核输出：

```text
State: t (tracing stop)
```

当前 ShadowPtrace 输出：

```text
State: t (tracing)
```

实现位置：`code/shadow_ptrace_hwdebug.c:1119`。

首字符 `t` 和 `TracerPid` 的语义已经对齐，但如果调用方比较完整字符串，
仍可能识别出差异。

### 4. 当前日志没有完整展示所有槽位

当前日志完整打印了 HW_BREAK 输入的 6 个槽位，但后续只显示了部分规范化
槽位；HW_WATCH 的详细槽位也没有完整打印。

这不是已确认的状态保存错误。`normalize_hwdebug()` 会遍历全部 16 个槽位，
而 GETREGSET 会写回完整的 `struct user_hwdebug_state`。缺少日志主要是因为
所有事件都通过 `pr_info_ratelimited()` 输出，同一槽位日志调用点触发了
内核限流。

实现位置：

- `code/shadow_ptrace_hwdebug.c:12`
- `code/shadow_ptrace_hwdebug.c:516`
- `code/shadow_ptrace_hwdebug.c:698`

因此当前日志可以证明调用顺序和返回值，但不能单独证明每个槽位的完整
读回内容。后续应将一次 hwdebug state 合并成单条日志，或者为该诊断路径
使用独立的限流策略。

## 后续修复优先级

1. ATTACH 前验证目标 task 是否存在；不存在时返回 `-ESRCH`，且不创建 session。
2. 对失败 ATTACH 的 wait4 保持真实的 `-ECHILD` 行为，不伪造停止事件。
3. DETACH 在没有有效 session 且目标不存在时返回 `-ESRCH`。
4. 将伪造的 status 状态文本改为 `t (tracing stop)`。
5. 改进 hwdebug 槽位日志，确保一次 SET/GET 的完整状态可以被核验。
6. 最后再决定是否需要模拟 `PTRACE_SETOPTIONS` 的 `-ESRCH/0` 竞态特征。

## 最终判断

当前版本已经覆盖 SGame 对有效目标执行 ShadowPtrace 的核心调用序列和
HW_BREAK/HW_WATCH 状态语义。失效目标分支仍与正常内核明显不同，必须在
修复目标存在性和 session 状态机后，才能称为完整复现正常 ptrace 流程。
