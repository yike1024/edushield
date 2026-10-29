# ============================================================================
# status.ps1 —— 一屏看清 9 个进程：PID 是否活、端口是否监听、HTTP 健康是否通过
#
#   pwsh scripts/status.ps1
#   pwsh scripts/status.ps1 -Json     # 机器可读输出（给 CI / 巡检用）
# ============================================================================
[CmdletBinding()]
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib/common.ps1')

$Root = (Resolve-Path -LiteralPath $Root).Path
$stateFile = Join-Path $Root '.run/state.json'

$state = @{}
if (Test-Path -LiteralPath $stateFile) {
    $obj = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($obj.services) { foreach ($p in $obj.services.PSObject.Properties) { $state[$p.Name] = $p.Value } }
}

function Test-Port([int]$Port) {
    try {
        $conn = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop
        return [bool]$conn
    } catch {
        $netstat = & netstat -ano 2>$null | Select-String -Pattern ":$Port\s" | Select-String -Pattern 'LISTENING'
        return [bool]$netstat
    }
}

$rows = @()
$services = Get-Services -Root $Root -Only @() -Group '' -IncludeDisabled
foreach ($svc in $services) {
    $envMap = Get-ServiceEnv -Root $Root -Service $svc
    $running = $false
    $procId = ''
    if ($state.ContainsKey($svc.id) -and $state[$svc.id].pid) {
        $procId = $state[$svc.id].pid
        $running = [bool](Get-Process -Id $procId -ErrorAction SilentlyContinue)
    }
    $listening = Test-Port $svc.port
    $probe = $null
    if ($listening) { $probe = Invoke-Probe -Service $svc -EnvMap $envMap -TimeoutSec 3 }

    $verdict = 'down'
    if ($running -and $listening -and $probe -and $probe.Ok) { $verdict = 'ok' }
    elseif ($running -and $listening) { $verdict = 'no-health' }
    elseif ($listening) { $verdict = 'port-only' }
    elseif ($running) { $verdict = 'starting' }

    $rows += [pscustomobject]@{
        id        = $svc.id
        group     = $svc.group
        port      = $svc.port
        enabled   = if ($svc.enabled -eq $false) { 'disabled' } else { 'on' }
        pid       = $procId
        listening = if ($listening) { 'yes' } else { 'no' }
        health    = if ($probe -and $probe.Ok) { "ok($($probe.Status))" } elseif ($probe) { "fail($($probe.Status))" } else { '-' }
        state     = $verdict
    }
}

if ($Json) {
    $rows | ConvertTo-Json -Depth 4
    return
}

Write-Host ''
Write-Host "EduShield 平台状态   ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
Write-Host "仓根：$Root" -ForegroundColor DarkGray
Write-Host ''
$rows | Format-Table -AutoSize id, group, port, enabled, pid, listening, health, state | Out-String | Write-Host

$ok = @($rows | Where-Object { $_.state -eq 'ok' }).Count
$on = @($rows | Where-Object { $_.enabled -eq 'on' }).Count
Write-Host "健康 $ok / 启用 $on" -ForegroundColor $(if ($ok -eq $on) { 'Green' } else { 'Yellow' })
Write-Host "日志：$Root\logs\<service>.out.log ；状态文件：$stateFile" -ForegroundColor DarkGray
