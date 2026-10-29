# ============================================================================
# dev-down.ps1 —— 按启动逆序停止 .run/state.json 里记录的进程（含子进程）
#
#   pwsh scripts/dev-down.ps1              # 停全部
#   pwsh scripts/dev-down.ps1 -Only brain  # 只停某个
# ============================================================================
[CmdletBinding()]
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string[]]$Only = @()
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib/common.ps1')

$Root = (Resolve-Path -LiteralPath $Root).Path
$stateFile = Join-Path $Root '.run/state.json'
if (-not (Test-Path -LiteralPath $stateFile)) {
    Write-Host "[dev-down] 没有 .run/state.json，说明不是用 dev-up 启动的" -ForegroundColor Yellow
    return
}

$obj = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
$remaining = [ordered]@{}
$stopped = 0

# 逆序停：前端 → 大脑 → adapter → serve
$entries = @()
if ($obj.services) {
    foreach ($prop in $obj.services.PSObject.Properties) {
        $entries += [pscustomobject]@{ id = $prop.Name; info = $prop.Value }
    }
}
$entries = $entries | Sort-Object { ($_.info.startedAt -replace '\D', '') } -Descending

foreach ($e in $entries) {
    if ($Only.Count -gt 0 -and ($Only -notcontains $e.id)) {
        $remaining[$e.id] = $e.info
        continue
    }
    $procId = $e.info.pid
    if (-not $procId) { continue }
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $proc) {
        Write-Host "[dev-down] $($e.id) pid=$procId 已不在运行" -ForegroundColor DarkGray
        continue
    }
    Write-Host "[dev-down] 停止 $($e.id) pid=$procId" -ForegroundColor Cyan
    try {
        # /T 连子进程一起杀（reasonix serve 会拉起工具子进程）
        if ($IsWindows -or $env:OS -eq 'Windows_NT') {
            & taskkill.exe /PID $procId /T /F | Out-Null
        } else {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
        $stopped++
    } catch {
        Write-Host "[dev-down] 停止 $($e.id) 失败：$($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if ($remaining.Count -gt 0) {
    Write-NoBom $stateFile (@{ updatedAt = (Get-Date).ToString('s'); services = $remaining } | ConvertTo-Json -Depth 6)
    Write-Host "[dev-down] 已停止 $stopped 个，保留 $($remaining.Count) 个在 state.json" -ForegroundColor Green
} else {
    Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
    Write-Host "[dev-down] 已停止 $stopped 个，state.json 已清空" -ForegroundColor Green
}
