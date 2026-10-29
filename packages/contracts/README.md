# packages/contracts —— 跨模块协议的唯一出处

模块之间只通过 HTTP 通信，所以"字段长什么样"就是全仓最重要的一份约定。
这份约定的**权威实现**在 `apps/brain/protocol/__init__.py`（Pydantic 模型 + `PROTO_VER`），
本目录负责把它暴露给非 Python 的模块（Go 的 reasonix 域、TypeScript 前端）。

## 为什么权威实现在 brain 而不是这里

协议是从大脑这一侧定义的（大脑是唯一编排者）：三张表 `TaskMessage / Finding / Report`
由大脑构造、校验、落库。把它放在 `apps/brain/` 里，大脑的测试可以直接跑；若搬到这里，
大脑就要反向依赖一个"共享包"，反而破坏了"模块可独立拷走"的性质。

本目录只做**派生**：从权威模型生成 JSON Schema，Go / TS 侧按 schema 校验，不手抄字段。

## 生成 schema

```bash
cd apps/brain
pip install -r requirements.txt

python - <<'PY'
import json, pathlib
from protocol import TaskMessage, Finding, Report

out = pathlib.Path("../../packages/contracts")
out.mkdir(parents=True, exist_ok=True)
for name, model in (("task-message", TaskMessage), ("finding", Finding), ("report", Report)):
    schema = model.model_json_schema()
    (out / f"{name}.schema.json").write_text(
        json.dumps(schema, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("wrote", name)
PY
```

生成的 `*.schema.json` **要提交**（前端和 Go 域会读它）；一旦和 `apps/brain/protocol/`
不一致，CI 里比对即可发现：

```bash
# 生成后如果 git diff 有变化，说明协议改动没同步 —— PR 里应当带上 schema 的 diff
git diff --exit-code packages/contracts
```

## 各语言怎么用

| 语言 / 模块 | 建议做法 |
|---|---|
| Python（brain / tir） | 直接 `from protocol import Finding`（tir 侧用同名 dataclass 对齐，字段名一致即可） |
| Go（pentest / logaudit / intel 的工具层） | 只消费 `findings[]` 的最小集：`type/severity/title/evidence/description/recommendation`；不需要完整 Finding（id/task_id 由大脑补） |
| TypeScript（前端） | 已有 `src/lib/aisoc-api.ts`；schema 用于类型生成或运行时校验 |

## 最小集 vs 完整集

- **部件产出（最小集）**：模型只输出 `{"findings":[{type,severity,title,evidence,description,recommendation}]}`。
  这是 prompt 里约束的格式，宽松到任何模型都能稳定产出。
- **大脑归一化（完整集）**：大脑补 `id / task_id / domain / target / tool / timestamp`，
  并把 `type` 映射到 `Domain`、`recommendation` 映射到 `remediation`，然后才落库成 Finding。

改这两层的字段，都要回 `docs/HTTP-CONTRACT.md` §5 同步。
