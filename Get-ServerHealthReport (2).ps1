#Requires -Version 5.1
<#
.SYNOPSIS
    Scans servers from CSV and generates a self-contained interactive HTML health
    dashboard with an in-page configuration panel.

.DESCRIPTION
    Performs concurrent Ping / DNS / TCP-port checks on every server.
    Optionally collects CPU load, memory, disk usage and last-reboot via WMI/CIM.
    Produces a single HTML file with Bootstrap 5 + Chart.js.  Open in any browser.

    System-metrics collection requires WinRM (port 5985) access to target servers.
    Use -SkipSystemMetrics to omit the WMI phase.

    PS 7+  : ForEach-Object -Parallel
    PS 5.1 : Runspace pool

.PARAMETER CsvPath
    Input CSV.  Required columns: ServerName, ApplicationName, Environment,
    ServerType, Status.  Default: .\Servers.csv

.PARAMETER OutputPath
    Output HTML file.  Default: .\ServerHealth_Dashboard.html

.PARAMETER PingTimeoutMs
    ICMP timeout per server in ms.  Default: 2000

.PARAMETER MaxConcurrency
    Max simultaneous threads.  Default: 50

.PARAMETER SkipSystemMetrics
    Skip WMI/CIM queries (CPU, RAM, disk, reboot).

.PARAMETER WmiTimeoutSec
    CIM operation timeout in seconds.  Default: 15

.EXAMPLE
    .\Get-ServerHealthReport.ps1

.EXAMPLE
    .\Get-ServerHealthReport.ps1 -SkipSystemMetrics -PingTimeoutMs 1000
#>
[CmdletBinding()]
param(
    [string] $CsvPath            = '.\Servers.csv',
    [string] $OutputPath         = '.\ServerHealth_Dashboard.html',
    [int]    $PingTimeoutMs      = 2000,
    [int]    $MaxConcurrency     = 50,
    [switch] $SkipSystemMetrics,
    [int]    $WmiTimeoutSec      = 15
)

$ErrorActionPreference = 'Continue'

#region ── Script-level constants ─────────────────────────────────────────────

$Script:IsPS7 = $PSVersionTable.PSVersion.Major -ge 7

$Script:PortMap = @{
    'Application Server' = 443
    'Database Server'    = 1433
    'ETL Server'         = 443
    'File Server'        = 445
}

$Script:EnvOrder = @{
    'DEV' = 0; 'TEST' = 1; 'REGN' = 2; 'PROD' = 3; 'PROD-DR' = 4
}

#endregion

#region ── Function: Invoke-ServerScan ────────────────────────────────────────

function Invoke-ServerScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]] $Servers,
        [int]    $PingTimeoutMs   = 2000,
        [int]    $MaxConcurrency  = 50,
        [bool]   $EnableWmi       = $true,
        [int]    $WmiTimeoutSec   = 15
    )

    Write-Host "`n[*] Starting scan ($($Servers.Count) entries) — WMI: $(if($EnableWmi){'ON'}else{'OFF'})" `
        -ForegroundColor Cyan

    $ScanBlock = {
        param(
            [PSCustomObject] $Srv,
            [int]            $TimeoutMs,
            [hashtable]      $PortMap,
            [bool]           $DoWmi,
            [int]            $WmiSec
        )

        $r = [PSCustomObject]@{
            ServerName      = $Srv.ServerName
            ApplicationName = $Srv.ApplicationName
            Environment     = $Srv.Environment
            ServerType      = $Srv.ServerType
            Status          = $Srv.Status
            # Ping / DNS / Port
            PingSuccess     = $false
            RoundTripTimeMs = $null
            TTL             = $null
            IPAddress       = $null
            HostName        = $null
            PortChecked     = $null
            PortOpen        = $null
            HealthStatus    = 'Unknown'
            ErrorMessage    = $null
            # System metrics
            CpuLoadPct      = $null
            MemTotalGB      = $null
            MemUsedGB       = $null
            MemUsedPct      = $null
            DiskTotalGB     = $null
            DiskUsedGB      = $null
            DiskUsedPct     = $null
            LastRebootUtc   = $null
            OSCaption       = $null
            WmiError        = $null
            ScanTimestamp   = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        }

        $sn = if ($Srv.ServerName) { $Srv.ServerName.Trim() } else { '' }
        if (-not $sn) {
            $r.HealthStatus = 'Invalid'
            $r.ErrorMessage = 'ServerName is empty in CSV row'
            return $r
        }
        $r.ServerName = $sn

        # ── DNS ──────────────────────────────────────────────────────────
        try {
            $entry      = [System.Net.Dns]::GetHostEntry($sn)
            $r.HostName = $entry.HostName
            $ipv4 = $entry.AddressList |
                Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
                Select-Object -First 1
            $r.IPAddress = if ($ipv4) { $ipv4.ToString() } else { $entry.AddressList[0].ToString() }
        }
        catch {
            $r.HealthStatus = 'DNS Failure'
            $r.ErrorMessage = 'DNS: ' + ($_.Exception.Message -replace '"', "'")
        }

        # ── Ping ─────────────────────────────────────────────────────────
        try {
            $ping   = New-Object System.Net.NetworkInformation.Ping
            $opts   = New-Object System.Net.NetworkInformation.PingOptions
            $opts.DontFragment = $false
            $buf    = New-Object byte[] 32
            $reply  = $ping.Send($sn, $TimeoutMs, $buf, $opts)
            $ping.Dispose()

            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $r.PingSuccess     = $true
                $r.RoundTripTimeMs = [int]$reply.RoundtripTime
                $r.TTL = if ($null -ne $reply.Options) { $reply.Options.Ttl } else { $null }
                if (-not $r.IPAddress) { $r.IPAddress = $reply.Address.ToString() }
            }
            else {
                $em = 'Ping: ' + $reply.Status.ToString()
                $r.ErrorMessage = if ($r.ErrorMessage) { $r.ErrorMessage + ' | ' + $em } else { $em }
            }
        }
        catch {
            $em = 'Ping: ' + ($_.Exception.Message -replace '"', "'")
            $r.ErrorMessage = if ($r.ErrorMessage) { $r.ErrorMessage + ' | ' + $em } else { $em }
        }

        # ── Port probe ────────────────────────────────────────────────────
        $st = if ($Srv.ServerType) { $Srv.ServerType } else { '' }
        $port = if ($PortMap.ContainsKey($st)) { $PortMap[$st] } else { 80 }
        $r.PortChecked = $port
        try {
            $tcp   = New-Object System.Net.Sockets.TcpClient
            $async = $tcp.BeginConnect($sn, $port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(2000, $false) -and $tcp.Connected) {
                $tcp.EndConnect($async); $r.PortOpen = $true
            } else { $r.PortOpen = $false }
            $tcp.Close(); $tcp.Dispose()
        }
        catch { $r.PortOpen = $false }

        # ── Health classification ─────────────────────────────────────────
        if ($r.PingSuccess) {
            $r.HealthStatus = if     ($r.RoundTripTimeMs -le 50)  { 'Healthy'  }
                              elseif ($r.RoundTripTimeMs -le 200) { 'Warning'  }
                              else                                 { 'Degraded' }
        } elseif ($r.HealthStatus -ne 'DNS Failure') {
            $r.HealthStatus = 'Critical'
        }

        # ── WMI / CIM system metrics (only if pingable and enabled) ───────
        if ($r.PingSuccess -and $DoWmi) {
            try {
                # Helper: try CimInstance first, fall back to WmiObject (PS5 DCOM)
                function _cim {
                    param($Class, $Cn, $Filter, $Sec)
                    $p = @{ ClassName=$Class; ComputerName=$Cn; OperationTimeoutSec=$Sec; ErrorAction='Stop' }
                    if ($Filter) { $p.Filter = $Filter }
                    try { return Get-CimInstance @p }
                    catch {
                        if (Get-Command 'Get-WmiObject' -ErrorAction SilentlyContinue) {
                            $w = @{ Class=$Class; ComputerName=$Cn; ErrorAction='Stop' }
                            if ($Filter) { $w.Filter = $Filter }
                            return Get-WmiObject @w
                        }
                        throw
                    }
                }

                # CPU – average load across all logical processors
                $cpuInst = _cim 'Win32_Processor' $sn $null $WmiSec
                $r.CpuLoadPct = [int](($cpuInst |
                    Measure-Object -Property LoadPercentage -Average).Average)

                # OS – memory + last boot
                $osInst = _cim 'Win32_OperatingSystem' $sn $null $WmiSec
                $totKB  = $osInst.TotalVisibleMemorySize
                $freeKB = $osInst.FreePhysicalMemory
                if ($totKB -gt 0) {
                    $r.MemTotalGB  = [math]::Round($totKB / 1MB, 2)
                    $r.MemUsedGB   = [math]::Round(($totKB - $freeKB) / 1MB, 2)
                    $r.MemUsedPct  = [int](($totKB - $freeKB) / $totKB * 100)
                }
                $r.OSCaption = ($osInst.Caption -replace 'Microsoft Windows ','Windows ').Trim()

                # LastBootUpTime – normalise to UTC ISO string
                $lbt = $osInst.LastBootUpTime
                if ($lbt -is [datetime]) {
                    $r.LastRebootUtc = $lbt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                } elseif ($lbt) {
                    # WMI returns a string in DMTF format: yyyyMMddHHmmss.xxxxxx+UTC
                    $r.LastRebootUtc = [System.Management.ManagementDateTimeConverter]::ToDateTime($lbt).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                }

                # Disk – C: drive
                $diskInst = _cim 'Win32_LogicalDisk' $sn "DeviceID='C:'" $WmiSec
                if ($diskInst -and $diskInst.Size -gt 0) {
                    $r.DiskTotalGB = [math]::Round($diskInst.Size / 1GB, 1)
                    $r.DiskUsedGB  = [math]::Round(($diskInst.Size - $diskInst.FreeSpace) / 1GB, 1)
                    $r.DiskUsedPct = [int](($diskInst.Size - $diskInst.FreeSpace) / $diskInst.Size * 100)
                }
            }
            catch {
                $wmiMsg = 'WMI: ' + ($_.Exception.Message -replace '"', "'" -replace "`n",' ')
                $r.WmiError = $wmiMsg
            }
        }

        return $r
    }   # end ScanBlock

    # ── Deduplicate ───────────────────────────────────────────────────────
    $seen   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $unique = [System.Collections.Generic.List[PSCustomObject]]::new()
    $dupes  = 0
    foreach ($s in $Servers) {
        $key = if ($s.ServerName) { $s.ServerName.Trim() } else { [string]::Empty }
        if ([string]::IsNullOrEmpty($key) -or $seen.Add($key)) { $unique.Add($s) } else { $dupes++ }
    }
    if ($dupes) { Write-Warning "[!] Skipped $dupes duplicate ServerName(s)." }

    $bag = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

    if ($Script:IsPS7) {
        Write-Host "[*] PS7 ForEach-Object -Parallel (ThrottleLimit: $MaxConcurrency)" -ForegroundColor Green
        $unique | ForEach-Object -Parallel {
            $res = & $using:ScanBlock $_ $using:PingTimeoutMs $using:PortMap $using:EnableWmi $using:WmiTimeoutSec
            ($using:bag).Add($res)
            $c = switch ($res.HealthStatus) {
                'Healthy' {'Green'} 'Warning' {'Yellow'} 'Degraded' {'DarkYellow'}
                'Critical' {'Red'} 'DNS Failure' {'Magenta'} default {'Gray'}
            }
            Write-Host ("  [+] {0,-35} -> {1}" -f $res.ServerName, $res.HealthStatus) -ForegroundColor $c
        } -ThrottleLimit $MaxConcurrency
    }
    else {
        Write-Host "[*] PS5 Runspace pool (max: $MaxConcurrency)" -ForegroundColor Green
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxConcurrency)
        $pool.Open()
        $jobs = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($s in $unique) {
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($ScanBlock).AddArgument($s).AddArgument($PingTimeoutMs).AddArgument($Script:PortMap).AddArgument($EnableWmi).AddArgument($WmiTimeoutSec)
            $jobs.Add(@{ PS=$ps; Handle=$ps.BeginInvoke(); Name=$s.ServerName })
        }

        foreach ($j in $jobs) {
            try {
                $res = $j.PS.EndInvoke($j.Handle)
                foreach ($item in $res) {
                    if ($null -ne $item) {
                        $bag.Add($item)
                        $c = switch ($item.HealthStatus) {
                            'Healthy' {'Green'} 'Warning' {'Yellow'} 'Degraded' {'DarkYellow'}
                            'Critical' {'Red'} 'DNS Failure' {'Magenta'} default {'Gray'}
                        }
                        Write-Host ("  [+] {0,-35} -> {1}" -f $item.ServerName, $item.HealthStatus) -ForegroundColor $c
                    }
                }
                if ($j.PS.HadErrors) { foreach ($e in $j.PS.Streams.Error) { Write-Warning "  [!] $($j.Name): $e" } }
            }
            catch { Write-Warning "  [!] $($j.Name): $($_.Exception.Message)" }
            finally { $j.PS.Dispose() }
        }
        $pool.Close(); $pool.Dispose()
    }

    Write-Host "[*] Scan complete – $($bag.Count) result(s).`n" -ForegroundColor Cyan
    return [array]$bag
}

#endregion

#region ── Function: ConvertTo-HtmlDashboard ──────────────────────────────────

function ConvertTo-HtmlDashboard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][PSCustomObject[]] $ScanResults,
        [Parameter(Mandatory)][string] $OutputPath
    )

    Write-Host "[*] Building HTML dashboard..." -ForegroundColor Cyan

    function _js  ([string]$s) {
        if ([string]::IsNullOrEmpty($s)) { return '' }
        $s = $s -replace '\\','\\\\'
        $s = $s -replace '"', '\"'
        $s = $s -replace "`r`n",'\n' -replace "`n",'\n' -replace "`r",'\n'
        $s = $s -replace "`t",'\t'
        return $s
    }
    function _num ($v)  { if ($null -eq $v) { 'null' }   else { [string]$v } }
    function _bool($v)  { if ($null -eq $v) { 'null' }   elseif ($v) { 'true' } else { 'false' } }
    function _fnum($v,$d=1) { if ($null -eq $v) { 'null' } else { [string][math]::Round($v,$d) } }

    $envKey = { param($n) if ($Script:EnvOrder.ContainsKey($n)) { $Script:EnvOrder[$n] } else { 99 } }

    # ── Aggregate stats ───────────────────────────────────────────────────
    $total    = $ScanResults.Count
    $healthy  = @($ScanResults | Where-Object HealthStatus -eq 'Healthy').Count
    $warning  = @($ScanResults | Where-Object HealthStatus -eq 'Warning').Count
    $degraded = @($ScanResults | Where-Object HealthStatus -eq 'Degraded').Count
    $critical = @($ScanResults | Where-Object { $_.HealthStatus -in 'Critical','DNS Failure','Invalid' }).Count
    $warnDeg  = $warning + $degraded

    $online   = @($ScanResults | Where-Object { $null -ne $_.RoundTripTimeMs })
    $avgPing  = if ($online.Count) { [math]::Round(($online | Measure-Object RoundTripTimeMs -Average).Average,1) } else { 0 }

    # WMI availability flag
    $withCpu  = @($ScanResults | Where-Object { $null -ne $_.CpuLoadPct })
    $withMem  = @($ScanResults | Where-Object { $null -ne $_.MemUsedPct })
    $hasWmi   = ($withCpu.Count + $withMem.Count) -gt 0
    $hasWmiJs = if ($hasWmi) { 'true' } else { 'false' }

    $avgCpu   = if ($withCpu.Count) { [math]::Round(($withCpu | Measure-Object CpuLoadPct -Average).Average,1) } else { $null }
    $avgMem   = if ($withMem.Count) { [math]::Round(($withMem | Measure-Object MemUsedPct -Average).Average,1) } else { $null }
    $avgCpuJs = if ($null -eq $avgCpu) { 'N/A' } else { "$avgCpu%" }
    $avgMemJs = if ($null -eq $avgMem) { 'N/A' } else { "$avgMem%" }

    $genTime  = Get-Date -Format 'dddd dd MMM yyyy  HH:mm:ss'
    $psVer    = $PSVersionTable.PSVersion.ToString()

    # ── Chart data ────────────────────────────────────────────────────────
    $envGrps    = $ScanResults | Group-Object Environment | Sort-Object { & $envKey $_.Name }
    $envLabels  = ($envGrps | ForEach-Object { '"'+(_js $_.Name)+'"' }) -join ','
    $envCounts  = ($envGrps | ForEach-Object { $_.Count }) -join ','

    $typeGrps   = $online | Group-Object ServerType | Sort-Object Name
    $typeLabels = ($typeGrps | ForEach-Object { '"'+(_js $_.Name)+'"' }) -join ','
    $typeAvgs   = ($typeGrps | ForEach-Object {
        [math]::Round(($_.Group | Measure-Object RoundTripTimeMs -Average).Average,1)
    }) -join ','

    $healthData = "$healthy,$warning,$degraded,$critical"

    # CPU chart – avg per Application
    $cpuAppGrps   = $withCpu | Group-Object ApplicationName | Sort-Object Name
    $cpuAppLabels = ($cpuAppGrps | ForEach-Object { '"'+(_js $_.Name)+'"' }) -join ','
    $cpuAppData   = ($cpuAppGrps | ForEach-Object {
        [math]::Round(($_.Group | Measure-Object CpuLoadPct -Average).Average,1)
    }) -join ','

    # Memory chart – avg % per ServerType
    $memTypeGrps   = $withMem | Group-Object ServerType | Sort-Object Name
    $memTypeLabels = ($memTypeGrps | ForEach-Object { '"'+(_js $_.Name)+'"' }) -join ','
    $memTypeData   = ($memTypeGrps | ForEach-Object {
        [math]::Round(($_.Group | Measure-Object MemUsedPct -Average).Average,1)
    }) -join ','

    # ── JSON tree ─────────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new(131072)
    [void]$sb.AppendLine('[')
    $appGroups = @($ScanResults | Group-Object ApplicationName | Sort-Object Name)

    for ($ai = 0; $ai -lt $appGroups.Count; $ai++) {
        $ag = $appGroups[$ai]
        $aH = @($ag.Group | Where-Object { $_.HealthStatus -eq 'Healthy' }).Count
        $aW = @($ag.Group | Where-Object { $_.HealthStatus -in 'Warning','Degraded' }).Count
        $aC = @($ag.Group | Where-Object { $_.HealthStatus -in 'Critical','DNS Failure','Invalid' }).Count
        $aS = if ($aC) { 'critical' } elseif ($aW) { 'warning' } else { 'healthy' }
        [void]$sb.AppendLine('  {')
        [void]$sb.AppendLine('    "app":"'+(_js $ag.Name)+'","appStatus":"'+$aS+'",' )
        [void]$sb.AppendLine("    `"appHealthy`":$aH,`"appWarning`":$aW,`"appCritical`":$aC,")
        [void]$sb.AppendLine('    "environments":[')
        $envGroups = @($ag.Group | Group-Object Environment | Sort-Object { & $envKey $_.Name })

        for ($ei = 0; $ei -lt $envGroups.Count; $ei++) {
            $eg = $envGroups[$ei]
            $eH = @($eg.Group | Where-Object { $_.HealthStatus -eq 'Healthy' }).Count
            $eW = @($eg.Group | Where-Object { $_.HealthStatus -in 'Warning','Degraded' }).Count
            $eC = @($eg.Group | Where-Object { $_.HealthStatus -in 'Critical','DNS Failure','Invalid' }).Count
            $eS = if ($eC) { 'critical' } elseif ($eW) { 'warning' } else { 'healthy' }
            [void]$sb.AppendLine('      {')
            [void]$sb.AppendLine('        "env":"'+(_js $eg.Name)+'","envStatus":"'+$eS+'",' )
            [void]$sb.AppendLine("        `"envHealthy`":$eH,`"envWarning`":$eW,`"envCritical`":$eC,")
            [void]$sb.AppendLine('        "servers":[')
            $srvList = @($eg.Group | Sort-Object ServerType, ServerName)

            for ($si = 0; $si -lt $srvList.Count; $si++) {
                $sv    = $srvList[$si]
                $comma = if ($si -lt $srvList.Count-1) { ',' } else { '' }
                [void]$sb.AppendLine(
                    '          {' +
                    '"name":"'    +(_js $sv.ServerName)     +'","app":"'  +(_js $sv.ApplicationName)+
                    '","env":"'   +(_js $sv.Environment)    +'","type":"' +(_js $sv.ServerType)+
                    '","csvStatus":"'+(_js $sv.Status)      +'","health":"'+(_js $sv.HealthStatus)+
                    '","ip":"'    +(_js $sv.IPAddress)      +'","hostname":"'+(_js $sv.HostName)+
                    '","ping":'   +(_num $sv.RoundTripTimeMs)+',"ttl":'   +(_num $sv.TTL)+
                    ',"port":'    +(_num $sv.PortChecked)   +',"portOpen":'+(_bool $sv.PortOpen)+
                    ',"cpu":'     +(_num $sv.CpuLoadPct)    +',"memTot":' +(_fnum $sv.MemTotalGB)+
                    ',"memUsed":' +(_fnum $sv.MemUsedGB)    +',"memPct":' +(_num $sv.MemUsedPct)+
                    ',"diskTot":' +(_fnum $sv.DiskTotalGB 1)+',"diskUsed":'+(_fnum $sv.DiskUsedGB 1)+
                    ',"diskPct":' +(_num $sv.DiskUsedPct)   +',"reboot":"'+(_js $sv.LastRebootUtc)+
                    '","os":"'    +(_js $sv.OSCaption)      +'","wmiErr":"'+(_js $sv.WmiError)+
                    '","error":"' +(_js $sv.ErrorMessage)   +'","ts":"'   +(_js $sv.ScanTimestamp)+
                    '"}'+$comma )
            }
            [void]$sb.AppendLine('        ]')
            $eComma = if ($ei -lt $envGroups.Count-1) { ',' } else { '' }
            [void]$sb.AppendLine("      }$eComma")
        }
        [void]$sb.AppendLine('    ]')
        $aComma = if ($ai -lt $appGroups.Count-1) { ',' } else { '' }
        [void]$sb.AppendLine("  }$aComma")
    }
    [void]$sb.AppendLine(']')
    $jsonData = $sb.ToString()

    # ── HTML template (single-quote = no PS interpolation) ─────────────
    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Server Health Dashboard</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" crossorigin="anonymous" />
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" crossorigin="anonymous" />
  <style>
    :root {
      --c-bg      : #0b1220;
      --c-surface : #141e30;
      --c-s2      : #1c2a40;
      --c-border  : #263348;
      --c-text    : #dde6f0;
      --c-muted   : #8898aa;
      --c-healthy : #34d399;
      --c-warning : #fbbf24;
      --c-degraded: #fb923c;
      --c-critical: #f87171;
      --c-dns     : #c084fc;
      --c-unknown : #64748b;
      --env-dev   : #60a5fa;
      --env-test  : #a78bfa;
      --env-regn  : #22d3ee;
      --env-prod  : #34d399;
      --env-pdr   : #fbbf24;
    }
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--c-bg);color:var(--c-text);font-family:'Segoe UI',system-ui,sans-serif;font-size:.875rem;min-height:100vh}

    /* ── Topbar ─────────────────────────────────── */
    .topbar{position:sticky;top:0;z-index:200;background:rgba(11,18,32,.96);
      border-bottom:1px solid var(--c-border);backdrop-filter:blur(10px);
      padding:.55rem 1.25rem;display:flex;align-items:center;gap:1rem}
    .topbar-brand{display:flex;align-items:center;gap:.5rem;font-weight:700;font-size:.95rem;white-space:nowrap}
    .topbar-brand i{color:#60a5fa;font-size:1.25rem}
    .topbar-nav{display:flex;gap:.25rem;margin-left:.5rem}
    .nav-tab{background:none;border:1px solid transparent;border-radius:7px;
      color:var(--c-muted);padding:.32rem .8rem;font-size:.78rem;cursor:pointer;
      transition:all .15s;display:flex;align-items:center;gap:.35rem}
    .nav-tab:hover{border-color:var(--c-border);color:var(--c-text)}
    .nav-tab.active{background:rgba(96,165,250,.12);border-color:rgba(96,165,250,.35);color:#60a5fa;font-weight:600}
    .topbar-meta{margin-left:auto;font-size:.68rem;color:var(--c-muted);display:flex;gap:.85rem;white-space:nowrap}
    .topbar-meta span{display:flex;align-items:center;gap:.3rem}

    /* ── Stat cards ─────────────────────────────── */
    .stat-grid{display:grid;grid-template-columns:repeat(8,1fr);gap:.6rem;margin-bottom:1.1rem}
    @media(max-width:1200px){.stat-grid{grid-template-columns:repeat(4,1fr)}}
    @media(max-width:640px) {.stat-grid{grid-template-columns:repeat(2,1fr)}}
    .stat-card{background:var(--c-surface);border:1px solid var(--c-border);border-radius:10px;
      padding:.85rem 1rem;position:relative;overflow:hidden;transition:transform .2s,box-shadow .2s}
    .stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;
      background:var(--accent,var(--c-muted));border-radius:10px 10px 0 0}
    .stat-card:hover{transform:translateY(-2px);box-shadow:0 8px 28px rgba(0,0,0,.45)}
    .stat-val{font-size:1.75rem;font-weight:800;line-height:1;color:var(--accent-text,var(--c-text))}
    .stat-lbl{margin-top:.25rem;font-size:.63rem;text-transform:uppercase;letter-spacing:.09em;color:var(--c-muted)}
    .stat-ico{position:absolute;right:.75rem;top:50%;transform:translateY(-50%);font-size:2.2rem;opacity:.08}

    /* ── Charts ─────────────────────────────────── */
    .chart-row{display:grid;gap:.65rem;margin-bottom:.65rem}
    .chart-row-3{grid-template-columns:repeat(3,1fr)}
    .chart-row-2{grid-template-columns:repeat(2,1fr)}
    @media(max-width:900px){.chart-row-3,.chart-row-2{grid-template-columns:1fr}}
    .chart-panel{background:var(--c-surface);border:1px solid var(--c-border);border-radius:10px;padding:1rem 1.1rem}
    .chart-panel-title{font-size:.63rem;text-transform:uppercase;letter-spacing:.1em;
      color:var(--c-muted);margin-bottom:.75rem;display:flex;align-items:center;gap:.4rem}

    /* ── Toolbar ─────────────────────────────────── */
    .toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem;margin-bottom:.9rem}
    .search-wrap{position:relative;flex:1;min-width:180px;max-width:340px}
    .search-icon{position:absolute;left:.7rem;top:50%;transform:translateY(-50%);color:var(--c-muted);pointer-events:none}
    .search-input{background:var(--c-surface);border:1px solid var(--c-border);border-radius:7px;
      padding:.48rem .7rem .48rem 2.1rem;color:var(--c-text);width:100%;font-size:.8rem;
      outline:none;transition:border-color .2s}
    .search-input:focus{border-color:#60a5fa}
    .search-input::placeholder{color:var(--c-muted)}
    .pill-group{display:flex;flex-wrap:wrap;gap:.3rem}
    .filter-pill{cursor:pointer;user-select:none;border:1px solid var(--c-border);border-radius:18px;
      padding:.22rem .65rem;font-size:.7rem;color:var(--c-muted);transition:all .15s;
      display:inline-flex;align-items:center;gap:.32rem}
    .filter-pill:hover,.filter-pill.active{border-color:#60a5fa;color:#60a5fa;font-weight:600}
    .filter-pill.active{background:rgba(96,165,250,.08)}
    .dp{width:7px;height:7px;border-radius:50%}
    .act-grp{display:flex;gap:.3rem;margin-left:auto}
    .act-btn{background:none;border:1px solid var(--c-border);border-radius:6px;color:var(--c-muted);
      padding:.28rem .6rem;font-size:.7rem;cursor:pointer;transition:all .15s;
      display:inline-flex;align-items:center;gap:.28rem}
    .act-btn:hover{border-color:#475569;color:var(--c-text)}

    /* ── App cards ───────────────────────────────── */
    .app-list{display:flex;flex-direction:column;gap:.7rem}
    .app-card{background:var(--c-surface);border:1px solid var(--c-border);border-radius:11px;overflow:hidden;transition:box-shadow .2s}
    .app-card:hover{box-shadow:0 4px 20px rgba(0,0,0,.35)}
    .app-hdr{display:flex;align-items:center;gap:.6rem;padding:.8rem 1rem;cursor:pointer;user-select:none;transition:background .15s}
    .app-hdr:hover{background:var(--c-s2)}
    .app-hdr.open{border-bottom:1px solid var(--c-border)}
    .app-icon-wrap{width:30px;height:30px;border-radius:7px;background:rgba(96,165,250,.1);
      border:1px solid rgba(96,165,250,.2);display:grid;place-items:center;flex-shrink:0;color:#60a5fa}
    .app-name{font-weight:600;font-size:.9rem;flex:1}
    .app-counts{display:flex;gap:.28rem}
    .cnt{font-size:.6rem;padding:.15rem .44rem;border-radius:9px;font-weight:700}
    .cnt-h{background:rgba(52,211,153,.1);color:var(--c-healthy);border:1px solid rgba(52,211,153,.2)}
    .cnt-w{background:rgba(251,191,36,.1);color:var(--c-warning);border:1px solid rgba(251,191,36,.2)}
    .cnt-c{background:rgba(248,113,113,.1);color:var(--c-critical);border:1px solid rgba(248,113,113,.2)}
    .app-chv{color:var(--c-muted);font-size:.76rem;transition:transform .25s}
    .app-chv.open{transform:rotate(90deg)}
    .app-body{display:none;padding:.8rem 1rem 1rem}
    .app-body.show{display:block}

    /* ── Env blocks ──────────────────────────────── */
    .env-block{margin-bottom:.55rem}
    .env-hdr{display:flex;align-items:center;gap:.45rem;padding:.4rem .72rem;border-radius:7px;
      border:1px solid var(--c-border);background:var(--c-s2);cursor:pointer;user-select:none;transition:border-color .15s}
    .env-hdr:hover{border-color:#344156}
    .env-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
    .env-lbl{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;flex:1}
    .env-meta{font-size:.65rem;color:var(--c-muted)}
    .env-chv{color:var(--c-muted);font-size:.68rem;transition:transform .22s}
    .env-chv.open{transform:rotate(90deg)}
    .env-body{display:none;margin-top:.38rem;padding-left:.15rem}
    .env-body.show{display:block}

    /* ── Type divider ────────────────────────────── */
    .type-div{display:flex;align-items:center;gap:.38rem;font-size:.6rem;text-transform:uppercase;
      letter-spacing:.12em;color:var(--c-muted);padding:.4rem 0 .18rem .38rem;
      border-left:2px solid var(--c-border);margin:.5rem 0 .22rem}

    /* ── Server rows ─────────────────────────────── */
    .srv-row{display:flex;align-items:center;gap:.5rem;padding:.42rem .6rem;border-radius:7px;
      border:1px solid var(--c-border);background:var(--c-bg);margin-bottom:.24rem;
      position:relative;transition:background .13s,border-color .13s}
    .srv-row:hover{background:var(--c-s2);border-color:#344156}
    .srv-row.hidden{display:none!important}

    .s-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
    .sd-Healthy    {background:var(--c-healthy); box-shadow:0 0 5px var(--c-healthy)}
    .sd-Warning    {background:var(--c-warning); box-shadow:0 0 5px var(--c-warning)}
    .sd-Degraded   {background:var(--c-degraded);box-shadow:0 0 5px var(--c-degraded)}
    .sd-Critical   {background:var(--c-critical);box-shadow:0 0 5px var(--c-critical);animation:blink 1.6s ease-in-out infinite}
    .sd-DNS-Failure{background:var(--c-dns);     box-shadow:0 0 5px var(--c-dns)}
    .sd-Unknown,.sd-Invalid{background:var(--c-unknown)}
    @keyframes blink{0%,100%{box-shadow:0 0 4px var(--c-critical)}50%{box-shadow:0 0 14px var(--c-critical)}}

    /* Named column wrappers for visibility toggling */
    .col-ip    {font-size:.72rem;font-family:monospace;color:var(--c-muted);min-width:105px}
    .col-ping  {font-size:.72rem;font-family:monospace;font-weight:700;min-width:62px}
    .col-port  {font-size:.68rem;min-width:82px}
    .col-cpu,.col-mem,.col-disk{min-width:76px}
    .col-reboot{font-size:.7rem;font-family:monospace;color:var(--c-muted);min-width:55px;text-align:right}
    .col-badge {flex-shrink:0}
    .srv-name  {font-size:.82rem;font-weight:500;min-width:130px;max-width:190px;
      white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .srv-spacer{flex:1}
    .port-open  {color:var(--c-healthy)}
    .port-closed{color:var(--c-critical)}
    .ping-fast{color:var(--c-healthy)}
    .ping-med {color:var(--c-warning)}
    .ping-slow{color:var(--c-degraded)}
    .ping-none{color:var(--c-unknown)}

    /* Metric mini-cells (CPU / Mem / Disk) */
    .mc{position:relative;display:inline-flex;align-items:center;justify-content:center;
      min-width:58px;height:19px;padding:0 .32rem;border-radius:4px;
      font-family:monospace;font-size:.68rem;font-weight:700;overflow:hidden}
    .mc::before{content:'';position:absolute;left:0;top:0;bottom:0;
      width:var(--pct,0%);background:currentColor;opacity:.15}
    .mc-ok  {color:var(--c-healthy); border:1px solid rgba(52,211,153,.2)}
    .mc-warn{color:var(--c-warning); border:1px solid rgba(251,191,36,.2)}
    .mc-crit{color:var(--c-critical);border:1px solid rgba(248,113,113,.2)}
    .mc-na  {color:var(--c-unknown); font-size:.68rem;font-family:monospace;min-width:24px;text-align:center}

    /* Health badge */
    .h-badge{font-size:.59rem;padding:.14rem .42rem;border-radius:9px;text-transform:uppercase;
      letter-spacing:.05em;font-weight:700;white-space:nowrap;flex-shrink:0}
    .hb-Healthy    {background:rgba(52,211,153,.1); color:var(--c-healthy); border:1px solid rgba(52,211,153,.2)}
    .hb-Warning    {background:rgba(251,191,36,.1); color:var(--c-warning); border:1px solid rgba(251,191,36,.2)}
    .hb-Degraded   {background:rgba(251,146,60,.1); color:var(--c-degraded);border:1px solid rgba(251,146,60,.2)}
    .hb-Critical   {background:rgba(248,113,113,.1);color:var(--c-critical);border:1px solid rgba(248,113,113,.2)}
    .hb-DNS-Failure{background:rgba(192,132,252,.1);color:var(--c-dns);    border:1px solid rgba(192,132,252,.2)}
    .hb-Unknown,.hb-Invalid{background:rgba(100,116,139,.1);color:var(--c-unknown);border:1px solid rgba(100,116,139,.2)}

    /* Tooltip */
    .tip{display:none;position:absolute;bottom:calc(100% + 7px);left:0;z-index:9999;
      background:var(--c-s2);border:1px solid var(--c-border);border-radius:9px;
      padding:.55rem .8rem;min-width:270px;box-shadow:0 10px 30px rgba(0,0,0,.55);pointer-events:none}
    .srv-row:hover .tip{display:block}
    .tip table{border-collapse:collapse}
    .tip td{padding:.07rem 0;vertical-align:top;font-size:.7rem}
    .tip td:first-child{color:var(--c-muted);padding-right:.85rem;white-space:nowrap;
      font-size:.65rem;text-transform:uppercase;letter-spacing:.05em}
    .tip td:last-child{font-family:monospace}
    .tip-err{color:var(--c-critical)!important;white-space:normal!important;font-family:sans-serif!important}
    .tip-sec{color:#60a5fa!important;font-weight:700!important;font-family:sans-serif!important;
      border-top:1px solid var(--c-border);padding-top:.35rem!important;margin-top:.2rem!important}

    /* Column-visibility toggles via body class */
    body.hide-ip     .col-ip     {display:none!important}
    body.hide-ping   .col-ping   {display:none!important}
    body.hide-port   .col-port   {display:none!important}
    body.hide-cpu    .col-cpu    {display:none!important}
    body.hide-mem    .col-mem    {display:none!important}
    body.hide-disk   .col-disk   {display:none!important}
    body.hide-reboot .col-reboot {display:none!important}
    body.hide-badge  .col-badge  {display:none!important}
    body.compact .srv-row        {padding:.26rem .5rem}
    body.compact .srv-name       {font-size:.77rem}
    body.compact .mc             {min-width:50px;height:17px;font-size:.63rem}

    /* No-results */
    .no-results{text-align:center;padding:3.5rem 1rem;color:var(--c-muted)}
    .no-results i{font-size:2.2rem;display:block;margin-bottom:.65rem}

    /* ── Settings page ───────────────────────────── */
    #cfgPage{max-width:940px;margin:0 auto;padding:1.25rem 1.25rem 3rem}
    .cfg-section-title{font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;
      color:var(--c-muted);margin:1.5rem 0 .65rem;display:flex;align-items:center;gap:.45rem}
    .cfg-card{background:var(--c-surface);border:1px solid var(--c-border);border-radius:10px;
      padding:1.1rem 1.25rem;margin-bottom:.75rem}
    .cfg-card-hdr{font-weight:600;font-size:.85rem;margin-bottom:.25rem;display:flex;align-items:center;gap:.45rem}
    .cfg-card-hdr i{color:#60a5fa}
    .cfg-card-desc{font-size:.72rem;color:var(--c-muted);margin-bottom:.9rem}
    .tog-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:.55rem .85rem}
    .tog{display:flex;align-items:center;gap:.55rem;cursor:pointer;user-select:none;
      font-size:.8rem;padding:.1rem 0}
    .tog input[type="checkbox"]{display:none}
    .tog-track{width:36px;height:19px;background:var(--c-border);border-radius:10px;
      position:relative;transition:background .2s;flex-shrink:0}
    .tog input:checked+.tog-track{background:#60a5fa}
    .tog-thumb{position:absolute;top:2px;left:2px;width:15px;height:15px;
      background:white;border-radius:50%;transition:left .18s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
    .tog input:checked+.tog-track .tog-thumb{left:19px}
    .tog-disabled{opacity:.45;pointer-events:none}

    .thr-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.6rem .85rem}
    .thr-row{display:flex;align-items:center;gap:.5rem;font-size:.78rem}
    .thr-lbl{min-width:90px;color:var(--c-muted);font-size:.72rem}
    .thr-sub{font-size:.68rem;color:var(--c-muted)}
    .thr-in{background:var(--c-bg);border:1px solid var(--c-border);border-radius:5px;
      color:var(--c-text);padding:.22rem .45rem;width:64px;font-family:monospace;
      font-size:.78rem;text-align:center;outline:none;transition:border-color .2s}
    .thr-in:focus{border-color:#60a5fa}

    .cfg-note{background:rgba(96,165,250,.07);border:1px solid rgba(96,165,250,.2);
      border-radius:7px;padding:.65rem .9rem;font-size:.75rem;color:#7eb8f7;
      display:flex;align-items:flex-start;gap:.55rem;margin-bottom:.65rem}
    .cfg-note i{flex-shrink:0;margin-top:.05rem}

    .cfg-footer{display:flex;gap:.65rem;justify-content:flex-end;margin-top:1.5rem}
    .cfg-btn-reset{background:none;border:1px solid rgba(248,113,113,.4);border-radius:7px;
      color:var(--c-critical);padding:.38rem .9rem;font-size:.78rem;cursor:pointer;
      transition:all .15s;display:flex;align-items:center;gap:.38rem}
    .cfg-btn-reset:hover{background:rgba(248,113,113,.08);border-color:var(--c-critical)}

    @media(max-width:600px){.tog-grid{grid-template-columns:1fr 1fr}.thr-grid{grid-template-columns:1fr}}
  </style>
</head>
<body>

<!-- ══════════════════ TOPBAR ══════════════════ -->
<header class="topbar">
  <div class="topbar-brand">
    <i class="bi bi-hdd-rack-fill"></i> Server Health Dashboard
  </div>
  <nav class="topbar-nav">
    <button id="navDash" class="nav-tab active" onclick="showPage('dash')">
      <i class="bi bi-speedometer2"></i> Dashboard
    </button>
    <button id="navCfg" class="nav-tab" onclick="showPage('cfg')">
      <i class="bi bi-gear-fill"></i> Settings
    </button>
  </nav>
  <div class="topbar-meta">
    <span><i class="bi bi-clock-history"></i>%%GEN_TIME%%</span>
    <span><i class="bi bi-terminal"></i>PS %%PS_VER%%</span>
  </div>
</header>

<!-- ══════════════════ DASHBOARD PAGE ══════════════════ -->
<div id="dashPage" style="max-width:1680px;margin:0 auto;padding:1.1rem 1.1rem 3rem">

  <!-- Stat cards -->
  <div class="stat-grid">
    <div class="stat-card" style="--accent:#60a5fa;--accent-text:#60a5fa">
      <div class="stat-val">%%TOTAL%%</div><div class="stat-lbl">Total Servers</div>
      <i class="bi bi-hdd-stack stat-ico"></i></div>
    <div class="stat-card" style="--accent:var(--c-healthy);--accent-text:var(--c-healthy)">
      <div class="stat-val">%%HEALTHY%%</div><div class="stat-lbl">Healthy</div>
      <i class="bi bi-check-circle stat-ico"></i></div>
    <div class="stat-card" style="--accent:var(--c-warning);--accent-text:var(--c-warning)">
      <div class="stat-val">%%WARN_DEG%%</div><div class="stat-lbl">Warn / Degraded</div>
      <i class="bi bi-exclamation-triangle stat-ico"></i></div>
    <div class="stat-card" style="--accent:var(--c-critical);--accent-text:var(--c-critical)">
      <div class="stat-val">%%CRITICAL%%</div><div class="stat-lbl">Critical / Offline</div>
      <i class="bi bi-x-circle stat-ico"></i></div>
    <div class="stat-card" style="--accent:#a78bfa;--accent-text:#a78bfa">
      <div class="stat-val">%%AVG_PING%%ms</div><div class="stat-lbl">Avg Ping</div>
      <i class="bi bi-activity stat-ico"></i></div>
    <div class="stat-card" style="--accent:#34d399;--accent-text:#34d399">
      <div class="stat-val">%%AVG_CPU%%</div><div class="stat-lbl">Avg CPU Load</div>
      <i class="bi bi-cpu stat-ico"></i></div>
    <div class="stat-card" style="--accent:#22d3ee;--accent-text:#22d3ee">
      <div class="stat-val">%%AVG_MEM%%</div><div class="stat-lbl">Avg Memory Used</div>
      <i class="bi bi-memory stat-ico"></i></div>
    <div class="stat-card" style="--accent:#38bdf8;--accent-text:#38bdf8">
      <div class="stat-val" id="visCount">%%TOTAL%%</div><div class="stat-lbl">Showing (filtered)</div>
      <i class="bi bi-funnel stat-ico"></i></div>
  </div>

  <!-- Charts row 1 -->
  <div class="chart-row chart-row-3" id="chartRow1">
    <div class="chart-panel" id="cpEnv">
      <div class="chart-panel-title"><i class="bi bi-pie-chart-fill"></i>Servers by Environment</div>
      <div style="position:relative;height:200px"><canvas id="chartEnv"></canvas></div>
    </div>
    <div class="chart-panel" id="cpType">
      <div class="chart-panel-title"><i class="bi bi-bar-chart-line-fill"></i>Avg Ping by Server Type (ms)</div>
      <div style="position:relative;height:200px"><canvas id="chartType"></canvas></div>
    </div>
    <div class="chart-panel" id="cpHealth">
      <div class="chart-panel-title"><i class="bi bi-clipboard2-pulse-fill"></i>Health Distribution</div>
      <div style="position:relative;height:200px"><canvas id="chartHealth"></canvas></div>
    </div>
  </div>

  <!-- Charts row 2 – system metrics (hidden until WMI data confirmed) -->
  <div class="chart-row chart-row-2" id="chartRow2" style="display:none">
    <div class="chart-panel" id="cpCpu">
      <div class="chart-panel-title"><i class="bi bi-cpu-fill"></i>Avg CPU Load by Application (%)</div>
      <div style="position:relative;height:200px"><canvas id="chartCpu"></canvas></div>
    </div>
    <div class="chart-panel" id="cpMem">
      <div class="chart-panel-title"><i class="bi bi-memory"></i>Avg Memory Usage by Server Type (%)</div>
      <div style="position:relative;height:200px"><canvas id="chartMem"></canvas></div>
    </div>
  </div>

  <!-- Toolbar -->
  <div class="toolbar">
    <div class="search-wrap">
      <i class="bi bi-search search-icon"></i>
      <input type="text" id="searchBox" class="search-input"
             placeholder="Search name or IP…" oninput="applyFilters()">
    </div>
    <div class="pill-group">
      <span class="filter-pill active" onclick="setFilter(this,'all')">All</span>
      <span class="filter-pill" onclick="setFilter(this,'Healthy')"><span class="dp" style="background:var(--c-healthy)"></span>Healthy</span>
      <span class="filter-pill" onclick="setFilter(this,'Warning')"><span class="dp" style="background:var(--c-warning)"></span>Warning</span>
      <span class="filter-pill" onclick="setFilter(this,'Degraded')"><span class="dp" style="background:var(--c-degraded)"></span>Degraded</span>
      <span class="filter-pill" onclick="setFilter(this,'Critical')"><span class="dp" style="background:var(--c-critical)"></span>Critical</span>
      <span class="filter-pill" onclick="setFilter(this,'DNS Failure')"><span class="dp" style="background:var(--c-dns)"></span>DNS Fail</span>
    </div>
    <div class="act-grp">
      <button class="act-btn" onclick="expandAll()"><i class="bi bi-arrows-expand"></i>Expand All</button>
      <button class="act-btn" onclick="collapseAll()"><i class="bi bi-arrows-collapse"></i>Collapse</button>
      <button class="act-btn" onclick="exportCsv()"><i class="bi bi-download"></i>Export CSV</button>
    </div>
  </div>

  <!-- App tree -->
  <div id="appTree" class="app-list"></div>
  <div id="noResults" class="no-results" style="display:none">
    <i class="bi bi-search"></i>No servers match the current filter.
  </div>

</div><!-- /dashPage -->

<!-- ══════════════════ SETTINGS PAGE ══════════════════ -->
<div id="cfgPage" style="display:none">

  <p class="cfg-section-title"><i class="bi bi-gear-fill"></i>Dashboard Configuration
    <span style="margin-left:auto;font-size:.65rem;color:var(--c-muted)">Changes apply instantly and persist in browser storage</span>
  </p>

  <!-- WMI unavailable notice -->
  <div class="cfg-note" id="cfgNoWmi" style="display:none">
    <i class="bi bi-info-circle-fill"></i>
    <span>CPU, Memory, and Disk data was not collected.
    Re-run the script without <code style="background:rgba(255,255,255,.07);padding:.05rem .3rem;border-radius:3px">-SkipSystemMetrics</code>
    and ensure WinRM (port 5985) is reachable on target servers.</span>
  </div>

  <!-- ─── CARD: Columns ─── -->
  <div class="cfg-card">
    <div class="cfg-card-hdr"><i class="bi bi-table"></i>Server Row Columns</div>
    <div class="cfg-card-desc">Show or hide individual data columns inside each server row.</div>
    <div class="tog-grid">
      <label class="tog"><input type="checkbox" id="cfg-showIp"     onchange="applyS('showIp',    this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>IP Address</label>
      <label class="tog"><input type="checkbox" id="cfg-showPing"   onchange="applyS('showPing',  this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Ping (ms)</label>
      <label class="tog"><input type="checkbox" id="cfg-showPort"   onchange="applyS('showPort',  this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Port Status</label>
      <label class="tog" id="tog-cpu"><input type="checkbox" id="cfg-showCpu"    onchange="applyS('showCpu',   this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>CPU Load %</label>
      <label class="tog" id="tog-mem"><input type="checkbox" id="cfg-showMem"    onchange="applyS('showMem',   this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Memory Usage</label>
      <label class="tog" id="tog-disk"><input type="checkbox" id="cfg-showDisk"   onchange="applyS('showDisk',  this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Disk Usage (C:)</label>
      <label class="tog" id="tog-reboot"><input type="checkbox" id="cfg-showReboot" onchange="applyS('showReboot',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Last Reboot</label>
      <label class="tog"><input type="checkbox" id="cfg-showBadge"  onchange="applyS('showBadge', this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Health Badge</label>
    </div>
  </div>

  <!-- ─── CARD: Charts ─── -->
  <div class="cfg-card">
    <div class="cfg-card-hdr"><i class="bi bi-bar-chart-fill"></i>Charts</div>
    <div class="cfg-card-desc">Toggle individual chart panels on or off.</div>
    <div class="tog-grid">
      <label class="tog"><input type="checkbox" id="cfg-chartEnv"    onchange="applyS('chartEnv',   this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Environment Distribution</label>
      <label class="tog"><input type="checkbox" id="cfg-chartType"   onchange="applyS('chartType',  this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Avg Ping by Type</label>
      <label class="tog"><input type="checkbox" id="cfg-chartHealth" onchange="applyS('chartHealth',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Health Distribution</label>
      <label class="tog" id="tog-chartCpu"><input type="checkbox" id="cfg-chartCpu"    onchange="applyS('chartCpu',   this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>CPU by Application</label>
      <label class="tog" id="tog-chartMem"><input type="checkbox" id="cfg-chartMem"    onchange="applyS('chartMem',   this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Memory by Server Type</label>
    </div>
  </div>

  <!-- ─── CARD: Thresholds ─── -->
  <div class="cfg-card">
    <div class="cfg-card-hdr"><i class="bi bi-sliders"></i>Health Thresholds</div>
    <div class="cfg-card-desc">Colour boundaries used to classify Healthy / Warning / Critical metrics.</div>
    <div class="thr-grid">

      <div>
        <div style="font-size:.7rem;color:var(--c-muted);font-weight:600;margin-bottom:.45rem;text-transform:uppercase;letter-spacing:.08em">
          <i class="bi bi-activity me-1"></i>Ping (ms)
        </div>
        <div class="thr-row">
          <span class="thr-lbl">Warning above</span>
          <input class="thr-in" type="number" id="thr-pingWarn" min="0" max="9999"
                 onchange="applyT('pingWarn',+this.value)">
          <span class="thr-sub">ms</span>
        </div>
        <div class="thr-row" style="margin-top:.3rem">
          <span class="thr-lbl">Degraded above</span>
          <input class="thr-in" type="number" id="thr-pingCrit" min="0" max="9999"
                 onchange="applyT('pingCrit',+this.value)">
          <span class="thr-sub">ms</span>
        </div>
      </div>

      <div>
        <div style="font-size:.7rem;color:var(--c-muted);font-weight:600;margin-bottom:.45rem;text-transform:uppercase;letter-spacing:.08em">
          <i class="bi bi-cpu me-1"></i>CPU Load (%)
        </div>
        <div class="thr-row">
          <span class="thr-lbl">Warning above</span>
          <input class="thr-in" type="number" id="thr-cpuWarn" min="0" max="100"
                 onchange="applyT('cpuWarn',+this.value)">
          <span class="thr-sub">%</span>
        </div>
        <div class="thr-row" style="margin-top:.3rem">
          <span class="thr-lbl">Critical above</span>
          <input class="thr-in" type="number" id="thr-cpuCrit" min="0" max="100"
                 onchange="applyT('cpuCrit',+this.value)">
          <span class="thr-sub">%</span>
        </div>
      </div>

      <div>
        <div style="font-size:.7rem;color:var(--c-muted);font-weight:600;margin-bottom:.45rem;text-transform:uppercase;letter-spacing:.08em">
          <i class="bi bi-memory me-1"></i>Memory Used (%)
        </div>
        <div class="thr-row">
          <span class="thr-lbl">Warning above</span>
          <input class="thr-in" type="number" id="thr-memWarn" min="0" max="100"
                 onchange="applyT('memWarn',+this.value)">
          <span class="thr-sub">%</span>
        </div>
        <div class="thr-row" style="margin-top:.3rem">
          <span class="thr-lbl">Critical above</span>
          <input class="thr-in" type="number" id="thr-memCrit" min="0" max="100"
                 onchange="applyT('memCrit',+this.value)">
          <span class="thr-sub">%</span>
        </div>
      </div>

      <div>
        <div style="font-size:.7rem;color:var(--c-muted);font-weight:600;margin-bottom:.45rem;text-transform:uppercase;letter-spacing:.08em">
          <i class="bi bi-device-hdd me-1"></i>Disk Used (%)
        </div>
        <div class="thr-row">
          <span class="thr-lbl">Warning above</span>
          <input class="thr-in" type="number" id="thr-diskWarn" min="0" max="100"
                 onchange="applyT('diskWarn',+this.value)">
          <span class="thr-sub">%</span>
        </div>
        <div class="thr-row" style="margin-top:.3rem">
          <span class="thr-lbl">Critical above</span>
          <input class="thr-in" type="number" id="thr-diskCrit" min="0" max="100"
                 onchange="applyT('diskCrit',+this.value)">
          <span class="thr-sub">%</span>
        </div>
      </div>

    </div>
  </div>

  <!-- ─── CARD: Behaviour ─── -->
  <div class="cfg-card">
    <div class="cfg-card-hdr"><i class="bi bi-toggles"></i>Behaviour</div>
    <div class="cfg-card-desc">General display and interaction preferences.</div>
    <div class="tog-grid">
      <label class="tog"><input type="checkbox" id="cfg-autoExpand"    onchange="applyS('autoExpand',   this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Auto-expand all on load</label>
      <label class="tog"><input type="checkbox" id="cfg-showArchived"  onchange="applyS('showArchived', this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Show Archived Servers</label>
      <label class="tog"><input type="checkbox" id="cfg-compactMode"   onchange="applyS('compactMode',  this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Compact Mode</label>
    </div>
  </div>

  <div class="cfg-footer">
    <button class="cfg-btn-reset" onclick="resetSettings()">
      <i class="bi bi-arrow-counterclockwise"></i> Reset to Defaults
    </button>
  </div>

</div><!-- /cfgPage -->

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js" crossorigin="anonymous"></script>
<script>
(function(){
'use strict';

/* ══════════════════ DATA ══════════════════ */
var DATA    = %%JSON_DATA%%;
var HAS_WMI = %%HAS_WMI%%;

var ENV_HEX = {'DEV':'#60a5fa','TEST':'#a78bfa','REGN':'#22d3ee','PROD':'#34d399','PROD-DR':'#fbbf24'};
var PALETTE  = ['#60a5fa','#a78bfa','#34d399','#fb923c','#f87171','#38bdf8','#fbbf24','#e879f9'];

/* ══════════════════ SETTINGS ══════════════════ */
var DEFAULTS = {
  showIp:true, showPing:true, showPort:true,
  showCpu:true, showMem:true, showDisk:true, showReboot:true, showBadge:true,
  chartEnv:true, chartType:true, chartHealth:true, chartCpu:true, chartMem:true,
  pingWarn:50, pingCrit:200,
  cpuWarn:70,  cpuCrit:90,
  memWarn:80,  memCrit:95,
  diskWarn:75, diskCrit:90,
  autoExpand:false, showArchived:true, compactMode:false
};
var S = Object.assign({}, DEFAULTS);

function loadSettings() {
  try {
    var raw = localStorage.getItem('srvDashCfg');
    if (raw) S = Object.assign({}, DEFAULTS, JSON.parse(raw));
  } catch(e) {}
}

function saveSettings() {
  try { localStorage.setItem('srvDashCfg', JSON.stringify(S)); } catch(e) {}
}

window.applyS = function(key, val) { S[key] = val; saveSettings(); applyAllSettings(); };

window.applyT = function(key, val) {
  S[key] = val;
  saveSettings();
  recolorMetrics();   // live threshold recolour – no tree rebuild needed
};

window.resetSettings = function() {
  S = Object.assign({}, DEFAULTS);
  saveSettings();
  syncCfgUI();
  applyAllSettings();
};

function applyAllSettings() {
  var b = document.body;
  b.classList.toggle('hide-ip',     !S.showIp);
  b.classList.toggle('hide-ping',   !S.showPing);
  b.classList.toggle('hide-port',   !S.showPort);
  b.classList.toggle('hide-cpu',    !S.showCpu);
  b.classList.toggle('hide-mem',    !S.showMem);
  b.classList.toggle('hide-disk',   !S.showDisk);
  b.classList.toggle('hide-reboot', !S.showReboot);
  b.classList.toggle('hide-badge',  !S.showBadge);
  b.classList.toggle('compact',      S.compactMode);

  showPanel('cpEnv',    S.chartEnv);
  showPanel('cpType',   S.chartType);
  showPanel('cpHealth', S.chartHealth);
  showPanel('cpCpu',    S.chartCpu    && HAS_WMI);
  showPanel('cpMem',    S.chartMem    && HAS_WMI);

  var row2Vis = HAS_WMI && (S.chartCpu || S.chartMem);
  var r2 = document.getElementById('chartRow2');
  if (r2) r2.style.display = row2Vis ? '' : 'none';

  applyFilters();
}

function showPanel(id, vis) {
  var el = document.getElementById(id);
  if (el) el.style.display = vis ? '' : 'none';
}

function syncCfgUI() {
  var bools = ['showIp','showPing','showPort','showCpu','showMem','showDisk','showReboot','showBadge',
               'chartEnv','chartType','chartHealth','chartCpu','chartMem',
               'autoExpand','showArchived','compactMode'];
  bools.forEach(function(k) {
    var el = document.getElementById('cfg-' + k);
    if (el) el.checked = S[k];
  });
  var nums = ['pingWarn','pingCrit','cpuWarn','cpuCrit','memWarn','memCrit','diskWarn','diskCrit'];
  nums.forEach(function(k) {
    var el = document.getElementById('thr-' + k);
    if (el) el.value = S[k];
  });
  // Dim WMI toggles if no data
  if (!HAS_WMI) {
    ['tog-cpu','tog-mem','tog-disk','tog-reboot','tog-chartCpu','tog-chartMem'].forEach(function(id) {
      var el = document.getElementById(id);
      if (el) el.classList.add('tog-disabled');
    });
    var note = document.getElementById('cfgNoWmi');
    if (note) note.style.display = '';
  }
}

/* ══════════════════ PAGE NAV ══════════════════ */
window.showPage = function(p) {
  document.getElementById('dashPage').style.display = p === 'dash' ? '' : 'none';
  document.getElementById('cfgPage').style.display  = p === 'cfg'  ? '' : 'none';
  document.getElementById('navDash').classList.toggle('active', p === 'dash');
  document.getElementById('navCfg').classList.toggle('active',  p === 'cfg');
  if (p === 'cfg') syncCfgUI();
};

/* ══════════════════ UTILS ══════════════════ */
function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function pingCls(ms) {
  if (ms === null || ms === undefined) return 'ping-none';
  return ms >= S.pingCrit ? 'ping-slow' : ms >= S.pingWarn ? 'ping-med' : 'ping-fast';
}

function metCls(pct, warn, crit) {
  if (pct === null || pct === undefined || isNaN(pct)) return '';
  return pct >= crit ? 'mc-crit' : pct >= warn ? 'mc-warn' : 'mc-ok';
}

function metCell(pct, warn, crit, label) {
  if (pct === null || pct === undefined) return '<span class="mc-na">—</span>';
  var cls = metCls(pct, warn, crit);
  var lbl = (label !== undefined && label !== null) ? label : pct + '%';
  return '<span class="mc ' + cls + '" style="--pct:' + Math.min(pct,100) + '%">' + esc(lbl) + '</span>';
}

function rebootAge(iso) {
  if (!iso) return '—';
  var d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  var mins = Math.floor((Date.now() - d.getTime()) / 60000);
  if (mins < 1)    return 'now';
  if (mins < 60)   return mins + 'm';
  if (mins < 1440) return Math.floor(mins/60) + 'h';
  return Math.floor(mins/1440) + 'd';
}

function rebootFull(iso) {
  if (!iso) return '—';
  var d = new Date(iso);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleString();
}

function dotCls(h)  { return 'sd-'  + String(h).replace(/\s/g,'-'); }
function badgeCls(h){ return 'hb-'  + String(h).replace(/\s/g,'-'); }

function typeIcon(t) {
  t = (t||'').toLowerCase();
  if (t.indexOf('database')>=0) return 'database-fill';
  if (t.indexOf('etl')>=0)      return 'arrow-left-right';
  if (t.indexOf('file')>=0)     return 'folder2-open';
  return 'display';
}

/* ══════════════════ BUILD TREE ══════════════════ */
function buildTree() {
  var tree = document.getElementById('appTree');
  tree.innerHTML = '';

  DATA.forEach(function(app, ai) {
    var pills = '';
    if (app.appHealthy)  pills += '<span class="cnt cnt-h"><i class="bi bi-check2"></i> ' + app.appHealthy  + '</span>';
    if (app.appWarning)  pills += '<span class="cnt cnt-w"><i class="bi bi-dash"></i> '   + app.appWarning  + '</span>';
    if (app.appCritical) pills += '<span class="cnt cnt-c"><i class="bi bi-x"></i> '      + app.appCritical + '</span>';
    var em = app.appStatus === 'critical' ? '🔴' : app.appStatus === 'warning' ? '🟡' : '🟢';

    var card = document.createElement('div');
    card.className = 'app-card';
    card.innerHTML =
      '<div class="app-hdr" id="ah-'+ai+'" onclick="togApp('+ai+')">' +
        '<div class="app-icon-wrap"><i class="bi bi-grid-3x3-gap-fill"></i></div>' +
        '<span class="app-name">' + esc(app.app) + '</span>' +
        '<div class="app-counts">' + pills + '</div>' +
        '<span style="font-size:.82rem">' + em + '</span>' +
        '<i class="bi bi-chevron-right app-chv" id="ac-'+ai+'"></i>' +
      '</div>' +
      '<div class="app-body" id="ab-'+ai+'"></div>';

    var body = card.querySelector('.app-body');

    app.environments.forEach(function(env, ei) {
      var ec   = ENV_HEX[env.env] || 'var(--c-muted)';
      var pvs  = env.servers.filter(function(s){ return s.ping!==null&&s.ping!==undefined; }).map(function(s){ return s.ping; });
      var avgP = pvs.length ? Math.round(pvs.reduce(function(a,b){return a+b;},0)/pvs.length) : null;
      var meta = env.servers.length + ' server' + (env.servers.length!==1?'s':'') +
                 (avgP!==null ? ' · avg '+avgP+'ms' : '');
      var cBadge = env.envCritical ? ' <span class="cnt cnt-c" style="font-size:.58rem">'+env.envCritical+' ✗</span>' : '';

      var envDiv = document.createElement('div');
      envDiv.className = 'env-block';
      envDiv.innerHTML =
        '<div class="env-hdr" onclick="togEnv('+ai+','+ei+')">' +
          '<span class="env-dot" style="background:'+ec+'"></span>' +
          '<span class="env-lbl" style="color:'+ec+'">' + esc(env.env) + '</span>' +
          '<span class="env-meta">' + meta + '</span>' + cBadge +
          '<i class="bi bi-chevron-right env-chv" id="ec-'+ai+'-'+ei+'"></i>' +
        '</div>' +
        '<div class="env-body" id="eb-'+ai+'-'+ei+'"></div>';

      var eBody = envDiv.querySelector('.env-body');
      var byType = {};
      env.servers.forEach(function(s){ if(!byType[s.type])byType[s.type]=[]; byType[s.type].push(s); });
      Object.keys(byType).sort().forEach(function(t) {
        var div = document.createElement('div');
        div.className = 'type-div';
        div.innerHTML = '<i class="bi bi-' + typeIcon(t) + '"></i>' + esc(t);
        eBody.appendChild(div);
        byType[t].forEach(function(srv){ eBody.appendChild(buildRow(srv)); });
      });
      body.appendChild(envDiv);
    });

    tree.appendChild(card);
    if (S.autoExpand) togApp(ai);
  });
}

function buildRow(srv) {
  var row = document.createElement('div');
  row.className = 'srv-row';
  row.setAttribute('data-health',    srv.health   || '');
  row.setAttribute('data-name',     (srv.name     || '').toLowerCase());
  row.setAttribute('data-ip',       (srv.ip       || '').toLowerCase());
  row.setAttribute('data-csvstatus', srv.csvStatus || '');
  // Store raw values for live recolouring on threshold change
  row.setAttribute('data-ms',   srv.ping    !== null && srv.ping    !== undefined ? srv.ping    : '');
  row.setAttribute('data-cpu',  srv.cpu     !== null && srv.cpu     !== undefined ? srv.cpu     : '');
  row.setAttribute('data-mem',  srv.memPct  !== null && srv.memPct  !== undefined ? srv.memPct  : '');
  row.setAttribute('data-disk', srv.diskPct !== null && srv.diskPct !== undefined ? srv.diskPct : '');

  var pingTxt = (srv.ping!==null&&srv.ping!==undefined) ? srv.ping+'ms' : 'N/A';
  var pCls    = pingCls(srv.ping);

  var portHtml = '';
  if (srv.port!==null&&srv.port!==undefined) {
    portHtml = srv.portOpen
      ? '<span class="port-open"><i class="bi bi-check2-circle"></i> :'+srv.port+'</span>'
      : '<span class="port-closed"><i class="bi bi-x-circle"></i> :'+srv.port+'</span>';
  }

  var memLbl  = (srv.memUsed!==null&&srv.memTot!==null&&srv.memUsed!==undefined&&srv.memTot!==undefined)
                  ? srv.memUsed+'/'+srv.memTot+'G' : null;
  var diskLbl = (srv.diskUsed!==null&&srv.diskTot!==null&&srv.diskUsed!==undefined&&srv.diskTot!==undefined)
                  ? srv.diskUsed+'/'+srv.diskTot+'G' : null;

  var errHtml = srv.error
    ? '<span class="srv-spacer" style="min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:160px;font-size:.67rem;color:var(--c-critical)" title="'+esc(srv.error)+'"><i class="bi bi-exclamation-circle"></i> '+esc(srv.error)+'</span>'
    : '<span class="srv-spacer"></span>';

  // Tooltip rows
  var tipBase =
    '<tr><td>Server</td><td>'    + esc(srv.name)            + '</td></tr>' +
    '<tr><td>Hostname</td><td>'  + esc(srv.hostname||'—')   + '</td></tr>' +
    '<tr><td>IP</td><td>'        + esc(srv.ip||'—')         + '</td></tr>' +
    '<tr><td>Ping</td><td>'      + ((srv.ping!==null&&srv.ping!==undefined)?srv.ping+'ms':'—') + '</td></tr>' +
    '<tr><td>TTL</td><td>'       + ((srv.ttl!==null&&srv.ttl!==undefined)?srv.ttl:'—')         + '</td></tr>' +
    '<tr><td>Port</td><td>'      + ((srv.port!==null&&srv.port!==undefined)?(srv.portOpen?'Open':'Closed')+' (:'+srv.port+')':'—') + '</td></tr>' +
    '<tr><td>Type</td><td>'      + esc(srv.type)             + '</td></tr>' +
    '<tr><td>CSV Status</td><td>'+ esc(srv.csvStatus||'—')  + '</td></tr>' +
    '<tr><td>Scanned</td><td>'   + esc(srv.ts)               + '</td></tr>';

  var tipWmi = '';
  if (HAS_WMI) {
    tipWmi =
      '<tr><td class="tip-sec" colspan="2">System Metrics</td></tr>' +
      '<tr><td>OS</td><td>'        + esc(srv.os||'—')         + '</td></tr>' +
      '<tr><td>CPU Load</td><td>'  + (srv.cpu!==null&&srv.cpu!==undefined?srv.cpu+'%':'—')       + '</td></tr>' +
      '<tr><td>Memory</td><td>'    + (memLbl?memLbl+' ('+srv.memPct+'%)':'—')                   + '</td></tr>' +
      '<tr><td>Disk C:</td><td>'   + (diskLbl?diskLbl+' ('+srv.diskPct+'%)':'—')                + '</td></tr>' +
      '<tr><td>Last Reboot</td><td>'+ rebootFull(srv.reboot) + '</td></tr>' +
      (srv.wmiErr ? '<tr><td>WMI Error</td><td class="tip-err">'+esc(srv.wmiErr)+'</td></tr>' : '');
  }
  var tipErr = srv.error ? '<tr><td>Error</td><td class="tip-err">'+esc(srv.error)+'</td></tr>' : '';

  row.innerHTML =
    '<span class="s-dot ' + dotCls(srv.health) + '"></span>' +
    '<span class="srv-name" title="'+esc(srv.name)+'">' + esc(srv.name) + '</span>' +
    '<span class="col-ip">'    + esc(srv.ip||'—') + '</span>' +
    '<span class="col-ping ' + pCls + '" data-ms="'+(srv.ping!==null&&srv.ping!==undefined?srv.ping:'')+'">'+pingTxt+'</span>' +
    '<span class="col-port">'  + portHtml + '</span>' +
    '<span class="col-cpu"  data-pct="'+(srv.cpu!==null&&srv.cpu!==undefined?srv.cpu:'')+'">'+  metCell(srv.cpu,  S.cpuWarn,  S.cpuCrit)  +'</span>' +
    '<span class="col-mem"  data-pct="'+(srv.memPct!==null&&srv.memPct!==undefined?srv.memPct:'')+'">'+metCell(srv.memPct,S.memWarn,S.memCrit,memLbl)+'</span>' +
    '<span class="col-disk" data-pct="'+(srv.diskPct!==null&&srv.diskPct!==undefined?srv.diskPct:'')+'">'+metCell(srv.diskPct,S.diskWarn,S.diskCrit,diskLbl)+'</span>' +
    '<span class="col-reboot" title="'+rebootFull(srv.reboot)+'">' + rebootAge(srv.reboot) + '</span>' +
    errHtml +
    '<span class="col-badge h-badge ' + badgeCls(srv.health) + '">' + esc(srv.health) + '</span>' +
    '<div class="tip"><table>' + tipBase + tipWmi + tipErr + '</table></div>';

  return row;
}

/* ══════════════════ LIVE THRESHOLD RECOLOUR ══════════════════ */
function recolorMetrics() {
  document.querySelectorAll('.col-ping[data-ms]').forEach(function(el) {
    var ms = el.getAttribute('data-ms');
    if (ms === '') return;
    el.className = 'col-ping ' + pingCls(+ms);
  });
  document.querySelectorAll('.col-cpu[data-pct]').forEach(function(el) {
    var pct = el.getAttribute('data-pct');
    if (pct === '') return;
    var inner = el.querySelector('.mc');
    if (inner) inner.className = 'mc ' + metCls(+pct, S.cpuWarn, S.cpuCrit);
  });
  document.querySelectorAll('.col-mem[data-pct]').forEach(function(el) {
    var pct = el.getAttribute('data-pct');
    if (pct === '') return;
    var inner = el.querySelector('.mc');
    if (inner) inner.className = 'mc ' + metCls(+pct, S.memWarn, S.memCrit);
  });
  document.querySelectorAll('.col-disk[data-pct]').forEach(function(el) {
    var pct = el.getAttribute('data-pct');
    if (pct === '') return;
    var inner = el.querySelector('.mc');
    if (inner) inner.className = 'mc ' + metCls(+pct, S.diskWarn, S.diskCrit);
  });
}

/* ══════════════════ TOGGLE / EXPAND ══════════════════ */
window.togApp = function(ai) {
  var body = document.getElementById('ab-'+ai);
  var hdr  = document.getElementById('ah-'+ai);
  var chv  = document.getElementById('ac-'+ai);
  var open = body.classList.toggle('show');
  chv.classList.toggle('open', open);
  hdr.classList.toggle('open', open);
};
window.togEnv = function(ai,ei) {
  var body = document.getElementById('eb-'+ai+'-'+ei);
  var chv  = document.getElementById('ec-'+ai+'-'+ei);
  body.classList.toggle('show');
  chv.classList.toggle('open');
};
window.expandAll = function() {
  document.querySelectorAll('.app-body').forEach(function(e){e.classList.add('show')});
  document.querySelectorAll('.env-body').forEach(function(e){e.classList.add('show')});
  document.querySelectorAll('.app-chv,.env-chv').forEach(function(e){e.classList.add('open')});
  document.querySelectorAll('.app-hdr').forEach(function(e){e.classList.add('open')});
};
window.collapseAll = function() {
  document.querySelectorAll('.app-body').forEach(function(e){e.classList.remove('show')});
  document.querySelectorAll('.env-body').forEach(function(e){e.classList.remove('show')});
  document.querySelectorAll('.app-chv,.env-chv').forEach(function(e){e.classList.remove('open')});
  document.querySelectorAll('.app-hdr').forEach(function(e){e.classList.remove('open')});
};

/* ══════════════════ FILTER ══════════════════ */
var activeFilter = 'all';

window.setFilter = function(el, f) {
  activeFilter = f;
  document.querySelectorAll('.filter-pill').forEach(function(p){p.classList.remove('active')});
  el.classList.add('active');
  applyFilters();
};

window.applyFilters = function() {
  var q     = (document.getElementById('searchBox').value||'').trim().toLowerCase();
  var count = 0;
  document.querySelectorAll('.srv-row').forEach(function(row) {
    var mf = activeFilter === 'all' || row.getAttribute('data-health') === activeFilter;
    var ms = !q || row.getAttribute('data-name').indexOf(q)>=0 || row.getAttribute('data-ip').indexOf(q)>=0;
    var ma = S.showArchived || row.getAttribute('data-csvstatus') !== 'Archived';
    var show = mf && ms && ma;
    row.classList.toggle('hidden', !show);
    if (show) count++;
  });
  document.getElementById('visCount').textContent = count;
  if (q || activeFilter !== 'all') {
    document.querySelectorAll('.app-card').forEach(function(card) {
      if (card.querySelector('.srv-row:not(.hidden)')) {
        card.querySelector('.app-body').classList.add('show');
        card.querySelector('.app-hdr').classList.add('open');
        card.querySelectorAll('.app-chv').forEach(function(c){c.classList.add('open')});
        card.querySelectorAll('.env-body').forEach(function(e){e.classList.add('show')});
        card.querySelectorAll('.env-chv').forEach(function(c){c.classList.add('open')});
      }
    });
  }
  document.getElementById('noResults').style.display = count===0 ? '' : 'none';
};

/* ══════════════════ CSV EXPORT ══════════════════ */
window.exportCsv = function() {
  var cols = ['ServerName','App','Env','Type','Health','IP','Hostname','PingMs','TTL',
              'Port','PortOpen','CPU%','MemTotGB','MemUsedGB','Mem%',
              'DiskTotGB','DiskUsedGB','Disk%','LastRebootUTC','OS','WmiError',
              'CSVStatus','Error','Timestamp'];
  var rows = [cols.join(',')];
  DATA.forEach(function(app){
    app.environments.forEach(function(env){
      env.servers.forEach(function(s){
        var cells = [
          s.name,s.app,s.env,s.type,s.health,s.ip,s.hostname,
          s.ping!==null&&s.ping!==undefined?s.ping:'',
          s.ttl!==null&&s.ttl!==undefined?s.ttl:'',
          s.port!==null&&s.port!==undefined?s.port:'',
          s.portOpen!==null&&s.portOpen!==undefined?s.portOpen:'',
          s.cpu!==null&&s.cpu!==undefined?s.cpu:'',
          s.memTot!==null&&s.memTot!==undefined?s.memTot:'',
          s.memUsed!==null&&s.memUsed!==undefined?s.memUsed:'',
          s.memPct!==null&&s.memPct!==undefined?s.memPct:'',
          s.diskTot!==null&&s.diskTot!==undefined?s.diskTot:'',
          s.diskUsed!==null&&s.diskUsed!==undefined?s.diskUsed:'',
          s.diskPct!==null&&s.diskPct!==undefined?s.diskPct:'',
          s.reboot||'',s.os||'',s.wmiErr||'',s.csvStatus||'',s.error||'',s.ts
        ];
        rows.push(cells.map(function(v){
          v=(v===null||v===undefined)?'':String(v);
          return(v.indexOf(',')>=0||v.indexOf('"')>=0||v.indexOf('\n')>=0)?'"'+v.replace(/"/g,'""')+'"':v;
        }).join(','));
      });
    });
  });
  var blob=new Blob([rows.join('\r\n')],{type:'text/csv;charset=utf-8;'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='ServerHealth_'+new Date().toISOString().slice(0,10).replace(/-/g,'')+'.csv';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
};

/* ══════════════════ CHARTS ══════════════════ */
var chartInstances = {};

function mkChart(id, cfg) {
  if (chartInstances[id]) { chartInstances[id].destroy(); }
  var el = document.getElementById(id);
  if (!el) return;
  chartInstances[id] = new Chart(el, cfg);
}

function initCharts() {
  Chart.defaults.color       = '#8898aa';
  Chart.defaults.borderColor = '#263348';
  var grid = 'rgba(38,51,72,.7)';
  var yScale = { beginAtZero:true, grid:{color:grid} };

  // 1. Environment doughnut
  var eL = [%%ENV_LABELS%%];
  var eD = [%%ENV_COUNTS%%];
  mkChart('chartEnv',{type:'doughnut',data:{labels:eL,datasets:[{data:eD,
    backgroundColor:eL.map(function(l){return ENV_HEX[l]||'#64748b';}),
    borderColor:'#0b1220',borderWidth:3,hoverOffset:6}]},
    options:{responsive:true,maintainAspectRatio:false,
      plugins:{legend:{position:'bottom',labels:{boxWidth:10,padding:9,color:'#8898aa'}},
               tooltip:{callbacks:{label:function(c){return ' '+c.label+': '+c.raw+' server'+(c.raw!==1?'s':'');}}}}}});

  // 2. Avg ping bar
  var tL=[%%TYPE_LABELS%%];var tD=[%%TYPE_AVGS%%];
  mkChart('chartType',{type:'bar',data:{labels:tL,datasets:[{label:'Avg Ping (ms)',data:tD,
    backgroundColor:tL.map(function(_,i){return PALETTE[i%PALETTE.length];}),
    borderRadius:5,borderSkipped:false}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
      scales:{x:{grid:{color:grid}},y:Object.assign({ticks:{callback:function(v){return v+'ms';}}},yScale)}}});

  // 3. Health distribution
  mkChart('chartHealth',{type:'bar',data:{labels:['Healthy','Warning','Degraded','Critical/Offline'],
    datasets:[{label:'Count',data:[%%HEALTH_DATA%%],
    backgroundColor:['#34d399','#fbbf24','#fb923c','#f87171'],borderRadius:5,borderSkipped:false}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
      scales:{x:{grid:{color:grid}},y:Object.assign({ticks:{stepSize:1}},yScale)}}});

  if (HAS_WMI) {
    document.getElementById('chartRow2').style.display = '';

    // 4. Avg CPU % by Application
    var cL=[%%CPU_APP_LABELS%%];var cD=[%%CPU_APP_DATA%%];
    mkChart('chartCpu',{type:'bar',data:{labels:cL,datasets:[{label:'Avg CPU %',data:cD,
      backgroundColor:cL.map(function(_,i){return PALETTE[i%PALETTE.length];}),
      borderRadius:5,borderSkipped:false}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
        scales:{x:{grid:{color:grid}},y:Object.assign({max:100,ticks:{callback:function(v){return v+'%';}}},yScale)}}});

    // 5. Avg Memory % by ServerType
    var mL=[%%MEM_TYPE_LABELS%%];var mD=[%%MEM_TYPE_DATA%%];
    mkChart('chartMem',{type:'bar',data:{labels:mL,datasets:[{label:'Avg Mem %',data:mD,
      backgroundColor:['#22d3ee','#a78bfa','#fb923c','#34d399'],
      borderRadius:5,borderSkipped:false}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
        scales:{x:{grid:{color:grid}},y:Object.assign({max:100,ticks:{callback:function(v){return v+'%';}}},yScale)}}});
  }
}

/* ══════════════════ INIT ══════════════════ */
document.addEventListener('DOMContentLoaded', function() {
  loadSettings();
  buildTree();
  applyAllSettings();
  initCharts();
  syncCfgUI();
});

}());
</script>
</body>
</html>
'@

    # ── Inject computed values ────────────────────────────────────────────
    $warnDeg = $warning + $degraded
    $html = $html.Replace('%%GEN_TIME%%',       $genTime)
    $html = $html.Replace('%%PS_VER%%',         $psVer)
    $html = $html.Replace('%%TOTAL%%',          [string]$total)
    $html = $html.Replace('%%HEALTHY%%',        [string]$healthy)
    $html = $html.Replace('%%WARN_DEG%%',       [string]$warnDeg)
    $html = $html.Replace('%%CRITICAL%%',       [string]$critical)
    $html = $html.Replace('%%AVG_PING%%',       [string]$avgPing)
    $html = $html.Replace('%%AVG_CPU%%',        $avgCpuJs)
    $html = $html.Replace('%%AVG_MEM%%',        $avgMemJs)
    $html = $html.Replace('%%JSON_DATA%%',      $jsonData)
    $html = $html.Replace('%%HAS_WMI%%',        $hasWmiJs)
    $html = $html.Replace('%%ENV_LABELS%%',     $envLabels)
    $html = $html.Replace('%%ENV_COUNTS%%',     $envCounts)
    $html = $html.Replace('%%TYPE_LABELS%%',    $typeLabels)
    $html = $html.Replace('%%TYPE_AVGS%%',      $typeAvgs)
    $html = $html.Replace('%%HEALTH_DATA%%',    $healthData)
    $html = $html.Replace('%%CPU_APP_LABELS%%', $cpuAppLabels)
    $html = $html.Replace('%%CPU_APP_DATA%%',   $cpuAppData)
    $html = $html.Replace('%%MEM_TYPE_LABELS%%',$memTypeLabels)
    $html = $html.Replace('%%MEM_TYPE_DATA%%',  $memTypeData)

    # ── Write file ────────────────────────────────────────────────────────
    $absPath  = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $parentDir = Split-Path $absPath -Parent
    if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
        New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
    }
    try {
        [System.IO.File]::WriteAllText($absPath, $html, [System.Text.Encoding]::UTF8)
        $kb = [math]::Round(([System.IO.FileInfo]$absPath).Length / 1KB, 1)
        Write-Host "[OK] Dashboard saved: $absPath  ($kb KB)" -ForegroundColor Green
    }
    catch { Write-Error "Failed to write HTML: $($_.Exception.Message)" }
}

#endregion

#region ── Main ───────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '╔══════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '║   Server Health Report Generator  v3.0           ║' -ForegroundColor Cyan
Write-Host '╚══════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Host "  PowerShell   : $($PSVersionTable.PSVersion)"       -ForegroundColor Gray
Write-Host "  CSV Input    : $CsvPath"                            -ForegroundColor Gray
Write-Host "  HTML Output  : $OutputPath"                         -ForegroundColor Gray
Write-Host "  Ping Timeout : ${PingTimeoutMs}ms"                  -ForegroundColor Gray
Write-Host "  Concurrency  : $MaxConcurrency threads"             -ForegroundColor Gray
Write-Host "  Sys Metrics  : $(if($SkipSystemMetrics){'DISABLED'}else{'ENABLED (WMI/CIM, '+$WmiTimeoutSec+'s timeout)'})" -ForegroundColor Gray
Write-Host ''

if (-not (Test-Path -LiteralPath $CsvPath)) {
    Write-Error "CSV file not found: '$CsvPath'"; exit 1
}

$csvData = Import-Csv -Path $CsvPath
$required = @('ServerName','ApplicationName','Environment','ServerType','Status')
$cols     = ($csvData | Get-Member -MemberType NoteProperty).Name
$missing  = $required | Where-Object { $_ -notin $cols }
if ($missing) { Write-Error "CSV missing column(s): $($missing -join ', ')"; exit 1 }

Write-Host "[*] Loaded $($csvData.Count) row(s) from '$CsvPath'." -ForegroundColor Cyan

$sw      = [System.Diagnostics.Stopwatch]::StartNew()
$results = Invoke-ServerScan -Servers $csvData `
               -PingTimeoutMs $PingTimeoutMs `
               -MaxConcurrency $MaxConcurrency `
               -EnableWmi (-not $SkipSystemMetrics.IsPresent) `
               -WmiTimeoutSec $WmiTimeoutSec
$sw.Stop()

Write-Host ("[*] Scan done in {0:n1}s — {1} result(s)" -f $sw.Elapsed.TotalSeconds, $results.Count) -ForegroundColor Cyan

if (-not $results -or $results.Count -eq 0) { $results = @() }

ConvertTo-HtmlDashboard -ScanResults $results -OutputPath $OutputPath

try {
    $abs    = (Get-Item -LiteralPath $OutputPath).FullName
    Write-Host "`n[*] Open in browser:" -ForegroundColor Green
    Write-Host "    file:///$($abs -replace '\\','/')" -ForegroundColor White
}
catch { Write-Host "`n[*] Report: $OutputPath" -ForegroundColor Green }

#endregion
