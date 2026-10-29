# ============================================================================
# gen-env.ps1 —— 从 config/env/*.env.tmpl + shared.env 渲染出各模块 .env
#
#   1. config/env/shared.env           （没有则从 shared.env.example 复制并自动填随机 token）
#   2. config/env/<id>.env             （渲染产物，唯一事实来源）
#   3. config/registry/brain.registry.json（由 .tmpl 渲染，token 自动填充）
#   4. 分发副本：apps/*/.env、各 reasonix home 的 .env、前端 .env.local
#
# 用法：
#   pwsh scripts/gen-env.ps1              # 全量渲染
#   pwsh scripts/gen-env.ps1 -Force      # 覆盖已存在的 shared.env
# ============================================================================
[CmdletBinding()]
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-NoBom([string]$path, [string]$text) {
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($path, $text, $utf8NoBom)
}

function Read-EnvFile([string]$path) {
    $map = [ordered]@{}
    if (-not (Test-Path -LiteralPath $path)) { return $map }
    foreach ($line in [System.IO.File]::ReadAllLines($path)) {
        $t = $line.Trim()
        if ($t.Length -eq 0 -or $t.StartsWith('#')) { continue }
        $i = $t.IndexOf('=')
        if ($i -lt 1) { continue }
        $k = $t.Substring(0, $i).Trim()
        $v = $t.Substring($i + 1)
        if ($v.Length -ge 2) {
            $q = $v.Substring(0, 1)
            if (($q -eq '"' -or $q -eq "'") -and $v.EndsWith($q)) { $v = $v.Substring(1, $v.Length - 2) }
        }
        $map[$k] = $v
    }
    return $map
}

# ${VAR} / ${VAR:-default} 展开；未知变量 -> 空串
function Expand-Template([string]$text, $map) {
    $pattern = '\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}'
    $evaluator = {
        param($m)
        $name = $m.Groups[1].Value
        if ($map.Contains($name) -and "$($map[$name])" -ne '') { return [string]$map[$name] }
        if ($m.Groups[2].Success -and $m.Groups[2].Value -ne '') { return [string]$m.Groups[2].Value }
        return ''
    }.GetNewClosure()
    return [regex]::Replace($text, $pattern, $evaluator)
}

# ---------------------------------------------------------------- 1) shared.env
$sharedPath = Join-Path $Root 'config/env/shared.env'
$sharedExample = Join-Path $Root 'config/env/shared.env.example'
if (-not (Test-Path -LiteralPath $sharedPath) -or $Force) {
    # 直接复制团队默认值（不随机生成）：clone 下来即可 dev-up
    Copy-Item -LiteralPath $sharedExample -Destination $sharedPath -Force
    Write-Host "[gen-env] 已生成 config/env/shared.env（团队默认值）" -ForegroundColor Yellow
}

$shared = Read-EnvFile $sharedPath
# 占位符（sk-xxxx）与空值都视为"未配置"：提示但不阻断渲染
$secretKeys = @('DEEPSEEK_API_KEY',
                'PENTEST_SERVE_TOKEN', 'PENTEST_PART_TOKEN',
                'LOGAUDIT_SERVE_TOKEN', 'LOGAUDIT_PART_TOKEN',
                'INTEL_SERVE_TOKEN', 'INTEL_PART_TOKEN')
$placeholders = @()
foreach ($k in $secretKeys) {
    $v = "$($shared[$k])"
    if ($v -eq '' -or $v -match 'xxxx') { $placeholders += $k }
}
if ($placeholders.Count -gt 0) {
    Write-Host "[gen-env] 提示：以下变量仍是占位符 sk-xxxx（或为空），跑真实任务前替换：" -ForegroundColor Yellow
    Write-Host "        $($placeholders -join ', ')" -ForegroundColor Yellow
    Write-Host "        改 config/env/shared.env 后重跑本脚本即可（无需 -Force）" -ForegroundColor DarkGray
}

# ------------------------------------------------- 2) 渲染 config/env/<id>.env
$rendered = @{}
foreach ($tmpl in Get-ChildItem -LiteralPath (Join-Path $Root 'config/env') -Filter '*.env.tmpl') {
    $id = $tmpl.Name -replace '\.env\.tmpl$', ''
    $text = Expand-Template ([System.IO.File]::ReadAllText($tmpl.FullName)) $shared
    $out = Join-Path $Root "config/env/$id.env"
    Write-NoBom $out $text
    $rendered[$id] = $out
    Write-Host "[gen-env] config/env/$id.env"
}

# ------------------------------------- 3) 渲染大脑部件注册表（token 来自 shared）
$regTmpl = Join-Path $Root 'config/registry/brain.registry.json.tmpl'
if (Test-Path -LiteralPath $regTmpl) {
    $text = Expand-Template ([System.IO.File]::ReadAllText($regTmpl)) $shared
    Write-NoBom (Join-Path $Root 'config/registry/brain.registry.json') $text
    Write-Host "[gen-env] config/registry/brain.registry.json"
}

# ------------------------------------------------------------- 4) 分发副本
$copies = @{
    'brain'    = @('apps/brain/.env')
    'tir'      = @('apps/tir/.env')
    'pentest'  = @('apps/pentest/.reasonix-home/.env')
    'logaudit' = @('apps/logaudit/.serve-home/.env')
    'intel'    = @('apps/intel/intel-agent/.reasonix-home/.env')
}
foreach ($id in $copies.Keys) {
    if (-not $rendered.ContainsKey($id)) { continue }
    $text = [System.IO.File]::ReadAllText($rendered[$id])
    foreach ($rel in $copies[$id]) {
        Write-NoBom (Join-Path $Root $rel) $text
        Write-Host "[gen-env] $rel"
    }
}

# 前端只注入 VITE_* 与端口（不能让前端 .env.local 拿到后端密钥）
if ($rendered.ContainsKey('frontend')) {
    $fe = Read-EnvFile $rendered['frontend']
    $lines = @(
        '# 由 scripts/gen-env.* 生成，勿手改',
        "VITE_BRAIN_API_URL=$($fe['VITE_BRAIN_API_URL'])",
        "REASONIX_DESKTOP_VITE_PORT=$($fe['REASONIX_DESKTOP_VITE_PORT'])"
    )
    Write-NoBom (Join-Path $Root 'apps/frontend/desktop/frontend/.env.local') (($lines -join "`n") + "`n")
    Write-Host "[gen-env] apps/frontend/desktop/frontend/.env.local"
}

Write-Host "[gen-env] 完成。改端口/加模块请改 config/services.json 与 config/env/*.env.tmpl。" -ForegroundColor Green
