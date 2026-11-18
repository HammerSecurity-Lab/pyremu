# 已知缺陷

条目按发现时间归档于 [known_issues/](known_issues/)。新增条目写入**当月**文件顶部
(最新在前); 当月文件不存在时按 `YYYY-MM.md` 新建, 并在下表登记。条目的写法沿用
既有分节: 现象 / 已确认 / 待验证 / 修复 (或 未修复)。

| 月份 | 条目数 | 文件 |
|------|--------|------|
| 2026-11 | 1 | [known_issues/2026-11.md](known_issues/2026-11.md) |
| 2026-10 | 1 | [known_issues/2026-10.md](known_issues/2026-10.md) |
| 2026-09 | 2 | [known_issues/2026-09.md](known_issues/2026-09.md) |
| 2026-08 | 1 | [known_issues/2026-08.md](known_issues/2026-08.md) |
| 2026-07 | 1 | [known_issues/2026-07.md](known_issues/2026-07.md) |

## 当前状态

| 发现日期 | 状态 | 条目 |
|----------|------|------|
| 2026-11-16 | 未修复 | [客机终端输入长行时整行被清空](known_issues/2026-11.md) |
| 2026-10-31 | 已修复 | [`restart` 之后 Ctrl+Q 不能暂停执行, 客机不再有输出](known_issues/2026-10.md) |
| 2026-09-14 | 待验证 | [AIA 模式: 空闲后首次输入的响应慢于连续输入](known_issues/2026-09.md) |
| 2026-09-03 | 已修复 | [宿主 Linux 未开 CONFIG_FPU → 硬浮点用户程序 SIGILL](known_issues/2026-09.md) |
| 2026-08-03 | 部分实现, 待验证 | [终端输入延迟 + Ctrl+C 不生效](known_issues/2026-08.md) |
| 2026-07-31 | 已修复, 待验证 | [多 hart WFI / TLB-shootdown IPI 死锁](known_issues/2026-07.md) |
