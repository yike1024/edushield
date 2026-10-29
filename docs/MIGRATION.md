# 从六个独立仓库 / 六个压缩包合并到这个仓

本仓当前的 `apps/` 已经放好了六个模块的源码（从六个 tar/zip 解压而来）。下一步就是把它
变成一个真正的 git 仓库。三条路，按"要不要保留各模块的提交历史"选。

## 方案 A：git subtree（推荐，保留历史）

适用于每个模块已经是一个独立 git 仓库的情况。新仓 `main` 从空开始：

```bash
mkdir edushield-platform && cd edushield-platform
git init -b main
git commit --allow-empty -m "chore: init monorepo skeleton"

# 把 6 个仓库依次并入 apps/<域>，保留各自历史
git subtree add --prefix apps/brain     <brain-repo-url>    main --squash
git subtree add --prefix apps/pentest   <pentest-repo-url>  main --squash
git subtree add --prefix apps/logaudit  <logaudit-repo-url> main --squash
git subtree add --prefix apps/intel     <intel-repo-url>    main --squash
git subtree add --prefix apps/tir       <tir-repo-url>      main --squash
git subtree add --prefix apps/frontend  <frontend-repo-url> main --squash
```

- `--squash`：只把每个仓库的当前状态压成一个提交（历史留在原仓库）。想完整拉历史就去掉它。
- 之后仍在**原仓库**开发时，用 `git subtree pull --prefix apps/<域> <url> main --squash` 同步；
  想改成"只在本仓开发"，就把原仓库归档并加一条 README 说明。
- subtree 的好处：`git clone` 一次拿到全部内容，不需要 `submodule update`，成员只会看到
  自己目录的 diff。

## 方案 B：直接搬目录（最快，丢历史）

六个模块本来就是压缩包发过来的话，这就是当前状态：

```bash
git init -b main
git add -A
git commit -m "chore: import six modules into monorepo layout"
```

历史从这一刻开始记。各模块内的 `CHANGELOG.md` / `docs/` 保留，作为历史证据。

## 方案 C：git submodule（不推荐）

submodule 适合"模块必须独立发版、独立 release"的场景，代价是：clone 要多一步
`git submodule update --init --recursive`，改跨模块代码时要来回切仓，CI 要处理递归。
本项目的模块虽然独立，但**发布节奏是一致的**（一起打包给校方），所以不值得付这个成本。

---

## 合并之后的日常

### 分支与提交

```
main                受保护，必须过 CI + 至少 1 个 review
feat/<域>/<主题>    例：feat/logaudit/retention-90d
fix/<域>/<主题>
chore/<主题>        跨域改动（配置、脚本、文档）
```

提交信息按域前缀，方便生成变更日志：

```
feat(pentest): adapter 增加内容风控重试上限
fix(tir): ingest 对空 evidence 降级为 parse_error
chore(config): 端口表补 intel 域
```

### 谁审谁的 PR

`CODEOWNERS` 已经把每个 `apps/<域>/` 派给对应成员。规则：

- 只动自己 `apps/<域>/` → 自己合并（可见性由 CI 保证）
- 动 `config/`、`scripts/`、`docs/` → 至少再拉一个域负责人
- 动 `apps/brain/protocol/` 或 `docs/HTTP-CONTRACT.md` → **全部域负责人**都要看到
  （这是唯一真正"跨模块"的代码）

### CI 只跑受影响的模块（路径过滤）

```yaml
# .github/workflows/ci.yml 的骨架
name: ci
on: [push, pull_request]
jobs:
  changes:
    runs-on: ubuntu-latest
    outputs:
      brain: ${{ steps.filter.outputs.brain }}
      pentest: ${{ steps.filter.outputs.pentest }}
      tir: ${{ steps.filter.outputs.tir }}
    steps:
      - uses: actions/checkout@v4
      - uses: dorny/paths-filter@v3
        id: filter
        with:
          filters: |
            brain: ['apps/brain/**', 'config/**']
            pentest: ['apps/pentest/**', 'config/**']
            tir: ['apps/tir/**', 'config/**']

  brain:
    needs: changes
    if: needs.changes.outputs.brain == 'true'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r apps/brain/requirements.txt
      - run: cd apps/brain && python -m pytest -q

  tir:
    needs: changes
    if: needs.changes.outputs.tir == 'true'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r apps/tir/requirements.txt
      - run: cd apps/tir && python -m threat_ir_agent doctor && python -m pytest -q
```

`config/**` 出现在每个 filter 里是刻意的：改端口/环境模板会影响所有域，值得全跑一遍。

### 加一个全局校验（很便宜的护栏）

```yaml
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: 仓库里不允许出现真实密钥
        run: |
          ! git grep -nE 'sk-[0-9a-f]{32}|sk-[A-Za-z0-9]{20,}' -- ':!*.md' || \
            (echo '发现疑似密钥，请改为环境变量' && exit 1)
      - name: 端口不允许写死在代码里（只允许在 config/ 与 scripts/）
        run: |
          ! git grep -nE '127\.0\.0\.1:8[0-9]{3}' -- 'apps/**/*.py' ':!**/.adapter.py.bak' || true
```

（第二条是提示性的，不阻断；逐步把硬编码端口清掉即可。）

---

## 反向能力：随时拆出去

这个结构**不锁定合并**。任何模块要拆出去独立部署：

```bash
git subtree split --prefix apps/logaudit -b logaudit-standalone
# 然后把 logaudit-standalone 推到独立仓库，独立构建镜像
```

拆出去后仍然符合 HTTP 契约（端口从环境变量来、token 从环境变量来），只是少了同仓的
`config/services.json` 编排 —— 用容器编排或 systemd 顶替即可。
