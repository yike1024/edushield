#!/usr/bin/env bash
# ============================================================================
# gen-env.sh —— 从 config/env/*.env.tmpl + shared.env 渲染出各模块 .env
#   与 scripts/gen-env.ps1 行为一致（Linux 服务器用这份）
# 用法：bash scripts/gen-env.sh [--force]
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FORCE="${1:-}"

# ---------------------------------------------------------------- 1) shared.env
if [ ! -f config/env/shared.env ] || [ "$FORCE" = "--force" ]; then
  # 直接复制团队默认值（不随机生成）：clone 下来即可 dev-up
  cp config/env/shared.env.example config/env/shared.env
  echo "[gen-env] 已生成 config/env/shared.env（团队默认值）"
fi

if grep -qE '^[A-Z_]+=.*xxxx' config/env/shared.env; then
  echo "[gen-env] 提示：config/env/shared.env 里仍是占位符 sk-xxxx，跑真实任务前替换（改完重跑本脚本）" >&2
fi

# ------------------------------------------------- 2) 渲染 config/env/<id>.env
python3 - <<'PY'
import pathlib, re

root = pathlib.Path('.')

def parse_env(path):
    data = {}
    if not path.exists():
        return data
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        k, v = line.split('=', 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
            v = v[1:-1]
        data[k.strip()] = v
    return data

shared = parse_env(root / 'config/env/shared.env')
pat = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}')

def expand(text, env):
    def sub(m):
        name, default = m.group(1), m.group(2)
        val = env.get(name) or ''
        if val:
            return val
        return default or ''
    return pat.sub(sub, text)

for tmpl in sorted((root / 'config/env').glob('*.env.tmpl')):
    sid = tmpl.name[:-len('.env.tmpl')]
    out = root / f'config/env/{sid}.env'
    out.write_text(expand(tmpl.read_text(encoding='utf-8'), shared), encoding='utf-8')
    print(f'[gen-env] config/env/{sid}.env')

# ------------------------------------- 3) 渲染大脑部件注册表
reg = root / 'config/registry/brain.registry.json.tmpl'
if reg.exists():
    (root / 'config/registry/brain.registry.json').write_text(
        expand(reg.read_text(encoding='utf-8'), shared), encoding='utf-8')
    print('[gen-env] config/registry/brain.registry.json')

# ------------------------------------------------------------- 4) 分发副本
copies = {
    'brain': ['apps/brain/.env'],
    'tir': ['apps/tir/.env'],
    'pentest': ['apps/pentest/.reasonix-home/.env'],
    'logaudit': ['apps/logaudit/.serve-home/.env'],
    'intel': ['apps/intel/intel-agent/.reasonix-home/.env'],
}
for sid, targets in copies.items():
    src = root / f'config/env/{sid}.env'
    if not src.exists():
        continue
    for t in targets:
        dst = root / t
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text(encoding='utf-8'), encoding='utf-8')
        print(f'[gen-env] {t}')

fe = root / 'config/env/frontend.env'
if fe.exists():
    fev = parse_env(fe)
    dst = root / 'apps/frontend/desktop/frontend/.env.local'
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(
        '# 由 scripts/gen-env.* 生成，勿手改\n'
        f"VITE_BRAIN_API_URL={fev.get('VITE_BRAIN_API_URL','/aisoc-brain/api')}\n"
        f"REASONIX_DESKTOP_VITE_PORT={fev.get('REASONIX_DESKTOP_VITE_PORT','5173')}\n",
        encoding='utf-8')
    print('[gen-env] apps/frontend/desktop/frontend/.env.local')
PY

echo "[gen-env] 完成。改端口/加模块请改 config/services.json 与 config/env/*.env.tmpl。"
