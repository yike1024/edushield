# ============================================================================
# common.ps1 —— 启动/状态脚本共用的小工具（不要直接运行，dot-source 使用）
#   . scripts/lib/common.ps1
# ============================================================================

$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-NoBom([string]$Path, [string]$Text) {
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    [System.IO.File]::WriteAllText($Path, $Text, $script:Utf8NoBom)
}

# 解析 .env / key=value 文件为有序字典（不展开变量）
function Read-EnvFile([string]$Path) {
    $map = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Path)) { return $map }
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $t = $line.Trim()
        if ($t.Length -eq 0 -or $t.StartsWith('#') -or $t.StartsWith(';')) { continue }
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

# ${VAR} / ${VAR:-default} 展开，未知变量 -> 空串
function Expand-Template([string]$Text, $Map) {
    $pattern = '\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}'
    $evaluator = {
        param($m)
        $name = $m.Groups[1].Value
        if ($Map.Contains($name) -and "$($Map[$name])" -ne '') { return [string]$Map[$name] }
        if ($m.Groups[2].Success -and $m.Groups[2].Value -ne '') { return [string]$m.Groups[2].Value }
        return ''
    }.GetNewClosure()
    return [regex]::Replace($Text, $pattern, $evaluator)
}

# 把服务需要的环境变量临时注入当前进程（子进程继承），返回快照用于恢复
function Enter-ServiceEnv($Map) {
    $snapshot = @{}
    foreach ($k in $Map.Keys) {
        $snapshot[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
        [Environment]::SetEnvironmentVariable($k, "$($Map[$k])", 'Process')
    }
    return $snapshot
}

function Exit-ServiceEnv($Snapshot) {
    foreach ($k in $Snapshot.Keys) {
        [Environment]::SetEnvironmentVariable($k, $Snapshot[$k], 'Process')
    }
}

# 解析 cmd 数组：展开 ${VAR}，可执行文件按 cwd 解析为绝对路径
function Resolve-ServiceCommand($CmdArray, [string]$Cwd, $EnvMap) {
    $expanded = @()
    foreach ($a in $CmdArray) { $expanded += (Expand-Template ([string]$a) $EnvMap) }

    $exe = $expanded[0]
    $args = @()
    if ($expanded.Count -gt 1) { $args = $expanded[1..($expanded.Count - 1)] }

    $isPath = $exe -match '[\\/]'
    if ($isPath) {
        $abs = if ([System.IO.Path]::IsPathRooted($exe)) { $exe } else { Join-Path $Cwd $exe }
        $abs = [System.IO.Path]::GetFullPath($abs)
        if (-not (Test-Path -LiteralPath $abs) -and (Test-Path -LiteralPath "$abs.exe")) { $abs = "$abs.exe" }
        return [pscustomobject]@{ Exe = $abs; Args = $args; Exists = (Test-Path -LiteralPath $abs) }
    }

    # PATH 查找
    $found = Get-Command $exe -ErrorAction SilentlyContinue
    return [pscustomobject]@{ Exe = $exe; Args = $args; Exists = [bool]$found }
}

# 单次 HTTP 探测（含 cookie 鉴权）
function Invoke-Probe($Service, $EnvMap, [int]$TimeoutSec = 4) {
    $health = $Service.health
    $url = "$($Service.baseUrl)$($health.path)"
    $headers = @{}
    if ($health.auth -eq 'cookie' -and $health.cookieVar) {
        $tok = "$($EnvMap[$health.cookieVar])"
        if ($tok) { $headers['Cookie'] = "$($health.cookieName)=$tok" }
    }
    try {
        $r = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing -TimeoutSec $TimeoutSec
        $ok = ($r.StatusCode -eq [int]$health.expect)
        return [pscustomobject]@{ Ok = $ok; Status = [int]$r.StatusCode; Note = '' }
    } catch {
        $code = 0
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        return [pscustomobject]@{ Ok = $false; Status = $code; Note = $_.Exception.Message }
    }
}

function Invoke-PostStart($Service, $EnvMap, [int]$TimeoutSec = 10) {
    if (-not $Service.postStart) { return }
    $ps = $Service.postStart
    $url = "$($Service.baseUrl)$($ps.path)"
    $headers = @{ 'Content-Type' = 'application/json' }
    if ($ps.cookieVar) {
        $tok = "$($EnvMap[$ps.cookieVar])"
        if ($tok) { $headers['Cookie'] = "reasonix_token=$tok" }
    }
    $body = ($ps.body | ConvertTo-Json -Compress)
    try {
        Invoke-WebRequest -Uri $url -Method ($ps.method) -Headers $headers -Body $body -UseBasicParsing -TimeoutSec $TimeoutSec | Out-Null
        Write-Host "        postStart OK -> $($ps.path) $body" -ForegroundColor DarkGray
    } catch {
        Write-Host "        postStart 失败（可手动重试）: $($ps.path) $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# 读 services.json 并按 startOrder 排序，附带过滤
function Get-Services([string]$Root, [string[]]$Only, [string]$Group, [switch]$IncludeDisabled) {
    $file = Join-Path $Root 'config/services.json'
    if (-not (Test-Path -LiteralPath $file)) { throw "缺少 $file" }
    $cfg = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json
    $list = @($cfg.services)
    if (-not $IncludeDisabled -and -not $Only) { $list = $list | Where-Object { $_.enabled -ne $false } }
    if ($Only -and $Only.Count -gt 0) { $list = $list | Where-Object { $Only -contains $_.id } }
    if ($Group) { $list = $list | Where-Object { $_.group -eq $Group } }
    return @($list | Sort-Object startOrder)
}

function Get-ServiceEnv([string]$Root, $Service) {
    $map = [ordered]@{}
    $files = @()
    if ($Service.envFile) { $files += $Service.envFile }
    if ($Service.extraEnvFiles) { $files += $Service.extraEnvFiles }
    foreach ($rel in $files) {
        $p = Join-Path $Root $rel
        foreach ($kv in (Read-EnvFile $p).GetEnumerator()) { $map[$kv.Key] = $kv.Value }
    }
    return $map
}
