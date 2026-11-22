# 协议与安全执行边界

<!-- doc-role: reference -->

项目级接口约定和安全职责见开发总纲。跨协议身份、授权、出口、流和恢复的检查点见执行契约。支持的协议版本和传输由当前实现及对应回归确定。[开发总纲](../DEV.md#安全与接口规范) · [统一安全执行约束](execution-contract.md)

## Android ARM64 LLM 安全验收

在已授权 ADB 的 Android ARM64 真机上，使用 `llm` Release CLI 运行回环验收。宿主需要 Python 3.11 或更新版本、系统 libcrypto 和 ADB。多设备环境可用 `--serial` 选择设备，ADB 不在 `PATH` 时可用 `--adb` 指定。[验收入口](../../tests/protocol/run_android_audit.py)

```sh
python3 tests/protocol/run_android_audit.py \
  --binary target/aarch64-linux-android/release/ai-security-platform \
  --report target/android-acceptance/audit.json
```

入口核对宿主与平板二进制的 SHA-256，使用独立测试目录和 ADB 回环转发检查鉴权、并发请求、SSE 和审计单写者约束。模型授权与出口许可分别用独立路由验证，检查 `403`、候选拒绝审计和上游零调用。SSE 取消用例在客户端接收首事件后断开，确认上游连接关闭、请求未重试且后续请求可正常处理。

故障阶段只限制测试网关进程的文件大小上限，等待真实追加返回 `EFBIG`，然后核对拒绝响应、上游零调用、审计隔离和持久记录字节。解除限制重启后重放同一份日志，并检查认证请求恢复和序号续接。每轮使用新的报告路径，网关日志保存在同名 `.logs` 目录。

## Android ARM64 LLM 性能基线

基线使用与成功安全验收报告 SHA-256 一致的 Release，保留 Enforce、可信 JWT、明确出口和 Required Audit。宿主使用同一确定性夹具测直连对照，再经 ADB 测平板。端到端延迟包含 ADB 转发与夹具等待时间。启动从宿主启动网关进程计到首次通过 readiness 和审计健康检查，每轮使用新的审计目录。[性能入口](../../tests/performance/run_android_baseline.py)

```sh
python3 tests/performance/run_android_baseline.py \
  --binary target/aarch64-linux-android/release/ai-security-platform \
  --acceptance target/android-acceptance/audit.json \
  --out target/android-performance/baseline --profile
```

默认测 HTTP 和 SSE 在并发 1、4、8、16 下的三轮表现，并在并发 8 下连续测 600 秒 SSE。报告保留原始请求样本、CPU 和内存采样、测试前后温度与电源状态，以及审计容量与健康状态。`--profile` 在独立的 HTTP C8 窗口采集用户态 CPU 热点。使用新输出目录保存每次测量。

候选配置可用 `--worker-threads 2 --concurrency 8 --rounds 1 --soak 600 --soak-protocols http sse --collect-stages` 验证。两个持续负载窗口分别启动网关并使用独立审计目录，各自保存窗口前后指标和审计状态。

HTTP 尾延迟复测可加 `--http-only --concurrency 8 16 --soak 0 --collect-stages`。每个负载窗口前后保存网关指标，直方图差值包含预热和正式请求。`--worker-threads` 用于独立运行的 worker 数对照。保持产物、负载和审计配置一致。

用 Android API 29 clang 将回环程序编译为可执行文件后由 `--relay` 指定，将同步探针编译为共享库后由 `--audit-sync-probe` 指定。回环程序保留两段 ADB 和模拟上游。同步探针计时测试审计目录中的 `fdatasync`，每条原始记录保存小端 `uint64` 的耗时纳秒及成功标记。使用独立短窗分析探针数据。[回环程序](../../tests/performance/android_probes/loopback_relay.c) · [同步探针](../../tests/performance/android_probes/audit_sync.c)

## 跨协议攻击回归

`cross-protocol-attacks` profile 使用真实 Gateway、本地 RAG／工具／Agent 替身与确定性模型输出，覆盖文档和工具返回注入、参数篡改、身份伪造、出口限制、Context 替换、撤销竞争及模型出口 PII。模型会按攻击计划产生工具调用，业务驱动将其提交到真实接口；以实际上游调用、工具副作用、响应披露和正常业务对照判定执行约束。它不测量真实模型被注入的概率，也不代表未知攻击检出率。

```sh
python3 tests/protocol/run_full_tcp.py --binary /absolute/path/to/ai-security-platform \
  --profile cross-protocol-attacks --rounds 1 --launcher sudo \
  --report /absolute/path/to/new-attack-report.json
```

产物需支持 LLM、MCP、A2A、RAG 和 Native PII；夹具显式启用 Enforce、可信 JWT、Context 及持久 Required Audit。详细输入、预期、实际调用和审计关联见报告的 `evidence`。该命令使用现有隔离回环入口，不访问云端。

`cross-protocol-corpus` profile使用[24例手写诊断对照](../../tests/protocol/fixtures/cross-protocol-content.json)，沿真实RAG→OpenAI兼容Mock API→MCP接口分别记录内容过滤与执行结果。上述命令替换profile为`cross-protocol-corpus`即可运行。报告的`detectionMetrics`给出精确率、召回率与正常样本误移除率；`executionMetrics`记录实际未授权工具调用尝试与副作用。Mock只按样本暴露情况产生预设工具调用，不执行语义推理，`realModelAttackSuccessRate`保持未评估。测试通过表示流程／观察和执行约束成立，不能代表检测准确率达标；这组人为对照不是生产分布或留出数据集。

用 `--profile context-guard-comparison` 在同一产物上比较 `legacy` 与 `contextual`。两套规则各运行诊断 24 例和[合成留出 12 例](../../tests/protocol/fixtures/context-guard-holdout.json)。`detectionComparison` 按样本集、规则集和家族汇总。验收要求既有检出样本逐例保持、留出集误删减少、诊断集误删无增加，并检查正常流程和实际工具副作用。结果只适用于这两组固定样本。
