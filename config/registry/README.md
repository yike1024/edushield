# 大脑部件注册表

`brain.registry.json.tmpl` 是**模板**，由 `scripts/gen-env.*` 渲染成 `brain.registry.json`
（含真实 token，已 gitignore）。大脑通过 `REGISTRY_FILE` 指向渲染产物：

```ini
# config/env/brain.env
REGISTRY_FILE=../../config/registry/brain.registry.json      # 相对 apps/brain
```

## 格式（严格，不能加注释键）

```json
{
  "<domain>": {
    "host": "127.0.0.1",
    "port": 8786,
    "token": "sk-...",
    "auth": "bearer",     // bearer | cookie
    "enabled": true
  }
}
```

- **顶层每个 key 就是一个 `domain`**，必须存在于 `apps/brain/protocol/__init__.py` 的
  `Domain` 枚举里（`pentest` / `logaudit` / `intel` / `incident` / `threatintel`）。
- 大脑的加载代码是 `PartSpec(domain=k, **v)`，所以**绝对不能放 `_comment` / `$note`
  这类非部件键**，否则启动时直接 TypeError。
- `auth` 决定大脑用哪种方式带凭据：`bearer` → `Authorization: Bearer <token>`；
  `cookie` → `Cookie: reasonix_token=<token>`。

## 端口对齐

registry 里的 `port` 必须与 `config/services.json` 里该域 **adapter 的端口**一致：

| domain | registry port | 对应的 services.json 条目 |
|---|---|---|
| pentest | 8786 | `pentest-adapter` |
| logaudit | 8788 | `logaudit-serve`（serve 直连，无 adapter） |
| intel | 8789 | `intel-adapter` |

不要把 registry 指向 reasonix serve 的 engine 端口（4523 / 8089），那是 adapter 专用的。

## 加一个新域

1. 在 `brain.registry.json.tmpl` 加一段（token 用 `${<域>_PART_TOKEN}`）；
2. `config/env/shared.env.example` 加同名 token；
3. `config/services.json` 加服务；
4. 确认 `Domain` 枚举里有这个域。

详见 `docs/ADD-MODULE.md`。
