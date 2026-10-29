# ============================================================================
# dev-up.ps1 —— 按 config/services.json 顺序拉起整套服务（每个模块仍是独立进程）
#
#   pwsh scripts/dev-up.ps1                 # 起全部 enabled 服务
#   pwsh scripts/dev-up.ps1 -Group pentest  # 只起渗透域（serve + adapter）
#   pwsh scripts/dev-up.ps1 -Only brain,tir # 只起指定服务
#   pwsh scripts/dev-up.ps1 -Strict         # 任一服务没起来就停下
# ============================================================================
[CmdletBinding()]
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [string[]]$Only = @(),
    [string]$Group = '',
    [int]$HealthTimeoutSec = 120,
    [switch]$Strict
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib/common.ps1')

$Root = (Resolve-Path -LiteralPath $Root).Path
$logDir = Join-Path $Root 'logs'
$runDir = Join-Path $Root '.run'
New-Item -ItemType Directory -Force -Path $logDir, $runDir | Out-Null
$stateFile = Join-Path $runDir 'state.json'

# ---- 环境文件先就位 ----
if (-not (Test-Path -LiteralPath (Join-Path $Root 'config/env/shared.env'))) {
    Write-Host "[dev-up] 缺少 config/env/shared.env，先执行 gen-env" -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot 'gen-env.ps1') -Root $Root
}

# ---- 读已有运行状态 ----
$state = @{}
if (Test-Path -LiteralPath $stateFile) {
    try {
        $obj = Get-Content -LiteralPath $stateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($obj.services) {
            foreach ($prop in $obj.services.PSObject.Properties) { $state[$prop.Name] = $prop.Value }
        }
    } catch { Write-Host "[dev-up] state.json 解析失败，忽略旧状态" -ForegroundColor Yellow }
}

$services = Get-Services -Root $Root -Only $Only -Group $Group
if ($services.Count -eq 0) { Write-Host "[dev-up] 没有匹配的服务" -ForegroundColor Yellow; return }

$results = New-Object System.Collections.ArrayList

foreach ($svc in $services) {
    $cwd = Join-Path $Root $svc.cwd
    Write-Host ''
    Write-Host "==> $($svc.id)   $($svc.baseUrl)   (cwd: $($svc.cwd))" -ForegroundColor Cyan

    # 已经在跑就跳过（重复启动会端口冲突）
    if ($state.ContainsKey($svc.id)) {
        $oldPid = $state[$svc.id].pid
        if ($oldPid -and (Get-Process -Id $oldPid -ErrorAction SilentlyContinue)) {
            Write-Host "    已在运行 pid=$oldPid，跳过（要重启先 dev-down）" -ForegroundColor DarkGray
            [void]$results.Add([pscustomobject]@{ id = $svc.id; state = 'already-running'; pid = $oldPid; port = $svc.port; note = '' })
            continue
        }
        $state.Remove($svc.id)
    }

    # ---- 检查工作目录与构建产物 ----
    if (-not (Test-Path -LiteralPath $cwd)) {
        Write-Host "    工作目录不存在：$cwd" -ForegroundColor Red
        [void]$results.Add([pscustomobject]@{ id = $svc.id; state = 'no-cwd'; pid = ''; port = $svc.port; note = $svc.cwd })
        if ($Strict) { break } else { continue }
    }
    $missing = @()
    foreach ($f in @($svc.preflightFiles)) {
        if (-not $f) { continue }
        $p = Join-Path $cwd $f
        if (-not (Test-Path -LiteralPath $p) -and -not (Test-Path -LiteralPath "$p.exe")) { $missing += $f }
    }
    if ($missing.Count -gt 0) {
        Write-Host "    缺少构建产物 $($missing -join ', ') —— 先在该目录 make build 生成 bin/reasonix" -ForegroundColor Red
        [void]$results.Add([pscustomobject]@{ id = $svc.id; state = 'need-build'; pid = ''; port = $svc.port; note = ($missing -join ',') })
        if ($Strict) { break } else { continue }
    }

    # ---- 环境注入 + 启动 ----
    $envMap = Get-ServiceEnv -Root $Root -Service $svc
    if ($envMap.Count -eq 0) { Write-Host "    警告：$($svc.envFile) 缺失或为空" -ForegroundColor Yellow }

    $resolved = Resolve-ServiceCommand -CmdArray $svc.cmd -Cwd $cwd -EnvMap $envMap
    if (-not $resolved.Exists) {
        Write-Host "    找不到可执行文件：$($resolved.Exe)（检查 shared.env 的 REASONIX_BIN）" -ForegroundColor Red
        [void]$results.Add([pscustomobject]@{ id = $svc.id; state = 'no-exe'; pid = ''; port = $svc.port; note = $resolved.Exe })
        if ($Strict) { break } else { continue }
    }

    $outLog = Join-Path $logDir "$($svc.id).out.log"
    $errLog = Join-Path $logDir "$($svc.id).err.log"
    Remove-Item -LiteralPath $outLog, $errLog -ErrorAction SilentlyContinue

    $snapshot = Enter-ServiceEnv $envMap
    try {
        $proc = Start-Process -FilePath $resolved.Exe -ArgumentList $resolved.Args `
            -WorkingDirectory $cwd -RedirectStandardOutput $outLog -RedirectStandardError $errLog `
            -PassThru -WindowStyle Hidden
    } finally {
        Exit-ServiceEnv $snapshot
    }
    Write-Host "    pid=$($proc.Id)  log=$($svc.id).out.log"

    # ---- 健康等待 ----
    $deadline = (Get-Date).AddSeconds($HealthTimeoutSec)
    $probe = $null
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 1500
        if ($proc.HasExited) { break }
        $probe = Invoke-Probe -Service $svc -EnvMap $envMap -TimeoutSec 4
        if ($probe.Ok) { break }
    }

    if ($proc.HasExited) {
        Write-Host "    进程已退出（code=$($proc.ExitCode)），最后 15 行日志：" -ForegroundColor Red
        if (Test-Path -LiteralPath $outLog) { Get-Content -LiteralPath $outLog -Tail 15 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } }
        if (Test-Path -LiteralPath $errLog) { Get-Content -LiteralPath $errLog -Tail 15 | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray } }
        [void]$results.Add([pscustomobject]@{ id = $svc.id; state = 'exited'; pid = $proc.Id; port = $svc.port; note = "code=$($proc.ExitCode)" })
        if ($Strict) { break } else { continue }
    }

    if (-not $probe -or -not $probe.Ok) {
        Write-Host "    ${HealthTimeoutSec}s 内健康检查未通过（status=$($probe.Status)），进程仍在运行，继续后续服务" -ForegroundColor Yellow
        [void]$results.Add([pscustomobject]@{ id = $svc.id; state = 'started-unhealthy'; pid = $proc.Id; port = $svc.port; note = "status=$($probe.Status)" })
    } else {
        Write-Host "    健康检查通过 ($($svc.health.path) -> $($probe.Status))" -ForegroundColor Green
        [void]$results.Add([pscustomobject]@{ id = $svc.id; state = 'healthy'; pid = $proc.Id; port = $svc.port; note = '' })
    }

    # ---- reasonix serve 的审批模式（auto/yolo）----
    Invoke-PostStart -Service $svc -EnvMap $envMap

    $state[$svc.id] = [pscustomobject]@{
        pid       = $proc.Id
        port      = $svc.port
        baseUrl   = $svc.baseUrl
        cwd       = $svc.cwd
        log       = $outLog
        startedAt = (Get-Date).ToString('s')
    }
    Write-NoBom $stateFile (@{ updatedAt = (Get-Date).ToString('s'); services = $state } | ConvertTo-Json -Depth 6)
}

# ---- 汇总 ----
Write-Host ''
Write-Host '==================== 启动汇总 ====================' -ForegroundColor Cyan
$results | Format-Table -AutoSize id, state, port, pid, note | Out-String | Write-Host
Write-Host "状态文件：$stateFile" -ForegroundColor DarkGray
Write-Host "日志目录：$logDir" -ForegroundColor DarkGray
Write-Host "查看状态：pwsh scripts/status.ps1" -ForegroundColor DarkGray
