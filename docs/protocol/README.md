# 协议与安全执行边界

<!-- doc-role: reference -->

项目级接口约定和安全职责见开发总纲。跨协议身份、授权、出口、流和恢复的检查点见执行契约。支持的协议版本和传输由当前实现及对应回归确定。[开发总纲](../DEV.md#安全与接口规范) · [统一安全执行约束](execution-contract.md)

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
