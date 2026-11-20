# fingerprint — 指纹图像与细节点比对载荷

面向飞地的用户态载荷, 由灰度指纹图像提取细节点, 或直接读取细节点数据,
计算 NIST NBIS 的 BOZORTH3 匹配分.

指纹传感器驱动不在此处: 载荷只接收图像或细节点数据, 驱动由宿主侧程序把传感器
输出整理成下述两种输入之一.

## 依赖

| crate | 版本 | 用途 | 许可 |
|-------|------|------|------|
| `fprint-mindtct` | 0.1.0 | 灰度图像到细节点 (MINDTCT) | MIT OR Apache-2.0 |
| `fprint-bozorth3` | 0.1.0 | 细节点比对 (BOZORTH3) | MIT OR Apache-2.0 |

两者均为无第三方依赖的 NIST NBIS 公有领域算法的 Rust 移植, 由 crates.io 取用,
不复制源码. 若上游停止维护, 再按本仓库既有方式改造.

## 构建

```bash
make          # 交叉编译 riscv64gc-unknown-linux-musl 静态 ELF
make host     # 在宿主上运行自检
```

产物为 `target/riscv64gc-unknown-linux-musl/release/fingerprint`, 静态链接,
可在飞地载荷环境中运行.

## 用法

```text
fingerprint match <probe.xyt> <gallery.xyt>
fingerprint image <probe.pgm> <gallery.pgm> [ppi]
fingerprint selftest
```

- `match`: 两个细节点文本文件直接比对. 每行取前三个整数 `x y theta`,
  空行与 `#` 开头的行忽略.
- `image`: 两个 P5 灰度图像 (最大灰度 255) 分别提取细节点后比对;
  `ppi` 为扫描分辨率, 默认 500. 像素按行优先读入, MINDTCT 以左下角为原点.
- `selftest`: 以内置的 12 枚细节点自检, 匹配分为 0 时以非零状态退出.

输出形如:

```text
minutiae probe=12 gallery=12
score=59 probe=12 gallery=12
```

匹配分范围 0 到 4000, 由调用方决定阈值.
