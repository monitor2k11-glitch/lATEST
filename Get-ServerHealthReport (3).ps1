#Requires -Version 5.1
<#
.SYNOPSIS
    Scans servers, checks URLs, and generates a self-contained interactive HTML dashboard.
.DESCRIPTION
    Phase 1 – Server scan (concurrent): Ping, DNS, port, WMI (CPU/RAM/Disk/reboot),
              Windows Services (services.ini), Event Logs, Hotfixes, Installed Apps.
    Phase 2 – URL check (concurrent): HTTP status/latency + IIS App Pool last recycle.
    Output   – Single HTML file with collapsible app tree, per-server detail panels,
              URL health rows, config page (all features togglable), Chart.js charts.

    services.ini format (CSV with .ini extension):
        ApplicationName,ServiceName
        MyApp,W3SVC
        MyApp,MyWorkerService

    urls.ini format:
        ApplicationName,URL
        MyApp,https://myapp.example.com/health

    WMI/CIM uses WinRM (port 5985).  Installed-app collection uses PSRemoting.
    Use -SkipSystemMetrics to skip all WMI/remote phases.

.PARAMETER CsvPath          Input servers CSV.    Default: .\Servers.csv
.PARAMETER OutputPath       Output HTML file.     Default: .\ServerHealth_Dashboard.html
.PARAMETER ServicesIniPath  Services watch list.  Default: .\services.ini
.PARAMETER UrlsIniPath      URLs watch list.      Default: .\urls.ini
.PARAMETER PingTimeoutMs    ICMP timeout (ms).    Default: 2000
.PARAMETER UrlTimeoutSec    HTTP timeout (s).     Default: 10
.PARAMETER MaxConcurrency   Server scan threads.  Default: 50
.PARAMETER WmiTimeoutSec    CIM timeout (s).      Default: 15
.PARAMETER SkipSystemMetrics  Skip all WMI/PSRemoting.
.PARAMETER SkipUrlCheck       Skip URL-check phase.
#>
[CmdletBinding()]
param(
    [string] $CsvPath           = '.\Servers.csv',
    [string] $OutputPath        = '.\ServerHealth_Dashboard.html',
    [string] $ServicesIniPath   = '.\services.ini',
    [string] $UrlsIniPath       = '.\urls.ini',
    [int]    $PingTimeoutMs     = 2000,
    [int]    $UrlTimeoutSec     = 10,
    [int]    $MaxConcurrency    = 50,
    [int]    $WmiTimeoutSec     = 15,
    [switch] $SkipSystemMetrics,
    [switch] $SkipUrlCheck
)

$ErrorActionPreference = 'Continue'

#region ── Constants ──────────────────────────────────────────────────────────
$Script:IsPS7    = $PSVersionTable.PSVersion.Major -ge 7
$Script:PortMap  = @{ 'Application Server'=443; 'Database Server'=1433; 'ETL Server'=443; 'File Server'=445 }
$Script:EnvOrder = @{ DEV=0; TEST=1; REGN=2; PROD=3; 'PROD-DR'=4 }

# ── Read services.ini → hashtable AppName → [ServiceName, …] ─────────────────
$Script:ServiceMap = @{}
if (Test-Path -LiteralPath $ServicesIniPath) {
    Import-Csv $ServicesIniPath | ForEach-Object {
        $a = $_.ApplicationName.Trim(); $s = $_.ServiceName.Trim()
        if (-not $Script:ServiceMap.ContainsKey($a)) { $Script:ServiceMap[$a] = [System.Collections.Generic.List[string]]::new() }
        $Script:ServiceMap[$a].Add($s)
    }
    Write-Host "[*] Loaded services.ini: $($Script:ServiceMap.Count) application(s)" -ForegroundColor Gray
}

# ── Read urls.ini → hashtable AppName → [URL, …] ─────────────────────────────
$Script:UrlMap = @{}
if (Test-Path -LiteralPath $UrlsIniPath) {
    Import-Csv $UrlsIniPath | ForEach-Object {
        $a = $_.ApplicationName.Trim(); $u = $_.URL.Trim()
        if (-not $Script:UrlMap.ContainsKey($a)) { $Script:UrlMap[$a] = [System.Collections.Generic.List[string]]::new() }
        $Script:UrlMap[$a].Add($u)
    }
    Write-Host "[*] Loaded urls.ini: $($Script:UrlMap.Count) application(s)" -ForegroundColor Gray
}
#endregion

#region ── Function: Invoke-ServerScan ───────────────────────────────────────
function Invoke-ServerScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][PSCustomObject[]] $Servers,
        [int]       $PingTimeoutMs  = 2000,
        [int]       $MaxConcurrency = 50,
        [bool]      $EnableWmi      = $true,
        [int]       $WmiTimeoutSec  = 15,
        [hashtable] $ServiceMap     = @{}
    )
    Write-Host "`n[*] Server scan – $($Servers.Count) entries | WMI: $(if($EnableWmi){'ON'}else{'OFF'})" -ForegroundColor Cyan

    $ScanBlock = {
        param([PSCustomObject]$Srv,[int]$Tms,[hashtable]$PM,[bool]$DoWmi,[int]$Wto,[hashtable]$SvcMap)

        $r = [PSCustomObject]@{
            ServerName=''; ApplicationName=$Srv.ApplicationName; Environment=$Srv.Environment
            ServerType=$Srv.ServerType; Status=$Srv.Status
            PingSuccess=$false; RoundTripTimeMs=$null; TTL=$null; IPAddress=$null; HostName=$null
            PortChecked=$null; PortOpen=$null; HealthStatus='Unknown'; ErrorMessage=$null
            CpuLoadPct=$null; MemTotalGB=$null; MemUsedGB=$null; MemUsedPct=$null
            DiskTotalGB=$null; DiskUsedGB=$null; DiskUsedPct=$null; LastRebootUtc=$null; OSCaption=$null
            Svcs=@(); Evts=@(); Patches=@(); Apps=@()
            ScanTimestamp=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        }

        $sn = if ($Srv.ServerName) { $Srv.ServerName.Trim() } else { '' }
        if (-not $sn) { $r.HealthStatus='Invalid'; $r.ErrorMessage='Empty ServerName'; return $r }
        $r.ServerName = $sn

        # DNS
        try {
            $e = [System.Net.Dns]::GetHostEntry($sn); $r.HostName = $e.HostName
            $ip4 = $e.AddressList | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -First 1
            $r.IPAddress = if ($ip4) { $ip4.ToString() } else { $e.AddressList[0].ToString() }
        } catch { $r.HealthStatus='DNS Failure'; $r.ErrorMessage='DNS: '+($_.Exception.Message -replace '"',"'") }

        # Ping
        try {
            $pg = New-Object System.Net.NetworkInformation.Ping
            $po = New-Object System.Net.NetworkInformation.PingOptions; $po.DontFragment=$false
            $reply = $pg.Send($sn,$Tms,(New-Object byte[] 32),$po); $pg.Dispose()
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                $r.PingSuccess=$true; $r.RoundTripTimeMs=[int]$reply.RoundtripTime
                $r.TTL = if ($null -ne $reply.Options) { $reply.Options.Ttl } else { $null }
                if (-not $r.IPAddress) { $r.IPAddress=$reply.Address.ToString() }
            } else {
                $em='Ping: '+$reply.Status
                $r.ErrorMessage=if($r.ErrorMessage){$r.ErrorMessage+' | '+$em}else{$em}
            }
        } catch {
            $em='Ping: '+($_.Exception.Message -replace '"',"'")
            $r.ErrorMessage=if($r.ErrorMessage){$r.ErrorMessage+' | '+$em}else{$em}
        }

        # Port
        $st=$Srv.ServerType; $port=if($PM.ContainsKey($st)){$PM[$st]}else{80}; $r.PortChecked=$port
        try {
            $tcp=$null; $tcp=New-Object System.Net.Sockets.TcpClient
            $a=$tcp.BeginConnect($sn,$port,$null,$null)
            if ($a.AsyncWaitHandle.WaitOne(2000,$false) -and $tcp.Connected) { $tcp.EndConnect($a); $r.PortOpen=$true } else { $r.PortOpen=$false }
            $tcp.Close(); $tcp.Dispose()
        } catch { $r.PortOpen=$false }

        # Health
        if ($r.PingSuccess) {
            $r.HealthStatus=if($r.RoundTripTimeMs -le 50){'Healthy'}elseif($r.RoundTripTimeMs -le 200){'Warning'}else{'Degraded'}
        } elseif ($r.HealthStatus -ne 'DNS Failure') { $r.HealthStatus='Critical' }

        # ── WMI / Remote block ────────────────────────────────────────────
        if (-not ($r.PingSuccess -and $DoWmi)) { return $r }

        function _cim { param($Cls,$Cn,$Fil,$Sec)
            $p=@{ClassName=$Cls;ComputerName=$Cn;OperationTimeoutSec=$Sec;ErrorAction='Stop'}
            if($Fil){$p.Filter=$Fil}
            try { Get-CimInstance @p }
            catch { if(Get-Command Get-WmiObject -EA SilentlyContinue){
                $w=@{Class=$Cls;ComputerName=$Cn;ErrorAction='Stop'}; if($Fil){$w.Filter=$Fil}; Get-WmiObject @w
            } else { throw } }
        }

        # CPU / Memory / Disk / Reboot / OS
        try {
            $cpu=_cim Win32_Processor $sn $null $Wto
            $r.CpuLoadPct=[int](($cpu|Measure-Object LoadPercentage -Average).Average)
            $os=_cim Win32_OperatingSystem $sn $null $Wto
            $tk=$os.TotalVisibleMemorySize; $fk=$os.FreePhysicalMemory
            if($tk -gt 0){ $r.MemTotalGB=[math]::Round($tk/1MB,2); $r.MemUsedGB=[math]::Round(($tk-$fk)/1MB,2); $r.MemUsedPct=[int](($tk-$fk)/$tk*100) }
            $r.OSCaption=($os.Caption -replace 'Microsoft Windows ','Windows ').Trim()
            $lbt=$os.LastBootUpTime
            $r.LastRebootUtc=if($lbt -is [datetime]){$lbt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')}
                             elseif($lbt){[System.Management.ManagementDateTimeConverter]::ToDateTime($lbt).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')}
                             else{$null}
            $dk=_cim Win32_LogicalDisk $sn "DeviceID='C:'" $Wto
            if($dk -and $dk.Size -gt 0){
                $r.DiskTotalGB=[math]::Round($dk.Size/1GB,1)
                $r.DiskUsedGB=[math]::Round(($dk.Size-$dk.FreeSpace)/1GB,1)
                $r.DiskUsedPct=[int](($dk.Size-$dk.FreeSpace)/$dk.Size*100)
            }
        } catch {
            $wm='WMI: '+($_.Exception.Message -replace '"',"'" -replace '[\r\n]',' ')
            $r.ErrorMessage=if($r.ErrorMessage){$r.ErrorMessage+' | '+$wm}else{$wm}
        }

        # Services (filtered by app name from services.ini)
        $appN=if($Srv.ApplicationName){$Srv.ApplicationName.Trim()}else{''}
        $r.Svcs=@()
        if ($SvcMap -and $SvcMap.ContainsKey($appN)) {
            foreach ($sv in $SvcMap[$appN]) {
                try {
                    $si=_cim Win32_Service $sn "Name='$sv'" $Wto
                    if($si){ $r.Svcs+=[PSCustomObject]@{N=$si.Name;D=$si.DisplayName;St=$si.State;Sm=$si.StartMode} }
                    else   { $r.Svcs+=[PSCustomObject]@{N=$sv;D=$sv;St='NotFound';Sm='—'} }
                } catch { $r.Svcs+=[PSCustomObject]@{N=$sv;D=$sv;St='Error';Sm='—'} }
            }
        }

        # Event Logs – Critical + Error, last 10
        $r.Evts=@()
        try {
            $evts=Get-WinEvent -ComputerName $sn -MaxEvents 10 `
                  -FilterHashtable @{LogName=@('Application','System');Level=@(1,2)} -ErrorAction Stop
            $r.Evts=@($evts|ForEach-Object {
                $msg=($_.Message -replace '"',"'" -replace '[\r\n\t]+',' ')
                [PSCustomObject]@{T=$_.TimeCreated.ToString('yyyy-MM-dd HH:mm');Lv=if($_.Level-eq 1){'Critical'}else{'Error'};
                    Src=($_.ProviderName -replace '"',"'");Id=$_.Id;Msg=if($msg.Length -gt 300){$msg.Substring(0,300)+'…'}else{$msg}}
            })
        } catch {
            try { # WMI fallback
                if(Get-Command Get-WmiObject -EA SilentlyContinue){
                    $cutoff=(Get-Date).AddDays(-7).ToUniversalTime().ToString("yyyyMMddHHmmss.000000+000")
                    $wevts=Get-WmiObject -ComputerName $sn -Class Win32_NTLogEvent -ErrorAction Stop `
                        -Filter "(Type='error') AND TimeGenerated>='$cutoff' AND (Logfile='Application' OR Logfile='System')" |
                        Sort-Object TimeGenerated -Descending | Select-Object -First 10
                    $r.Evts=@($wevts|ForEach-Object {
                        $msg=($_.Message -replace '"',"'" -replace '[\r\n\t]+',' ')
                        [PSCustomObject]@{T=([System.Management.ManagementDateTimeConverter]::ToDateTime($_.TimeGenerated)).ToString('yyyy-MM-dd HH:mm');
                            Lv='Error';Src=($_.SourceName -replace '"',"'");Id=$_.EventCode;
                            Msg=if($msg.Length -gt 300){$msg.Substring(0,300)+'…'}else{$msg}}
                    })
                }
            } catch {}
        }

        # Hotfixes – latest 5 KB updates
        $r.Patches=@()
        try {
            $hf=_cim Win32_QuickFixEngineering $sn $null $Wto |
                Where-Object { $_.HotFixID -match 'KB' } |
                Sort-Object InstalledOn -Descending | Select-Object -First 5
            $r.Patches=@($hf|ForEach-Object {
                $d=if($_.InstalledOn){try{([DateTime]$_.InstalledOn).ToString('yyyy-MM-dd')}catch{[string]$_.InstalledOn}}else{'—'}
                [PSCustomObject]@{Id=$_.HotFixID;Date=$d;Desc=($_.Description -replace '"',"'");By=($_.InstalledBy -replace '"',"'")}
            })
        } catch {}

        # Installed apps – latest 10 by install date via PSRemoting
        $r.Apps=@()
        try {
            $so=New-PSSessionOption -OperationTimeout($Wto*1000) -OpenTimeout($Wto*1000)
            $raw=Invoke-Command -ComputerName $sn -SessionOption $so -ErrorAction Stop -ScriptBlock {
                $paths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
                $all=foreach($p in $paths){ Get-ItemProperty $p -EA SilentlyContinue|Where-Object DisplayName|
                    Select-Object DisplayName,DisplayVersion,InstallDate,Publisher }
                $all|Sort-Object {
                    if($_.InstallDate -match '^\d{8}$'){[DateTime]::ParseExact($_.InstallDate,'yyyyMMdd',$null)}else{[DateTime]::MinValue}
                } -Descending | Select-Object -First 10
            }
            $r.Apps=@($raw|ForEach-Object{
                [PSCustomObject]@{N=($_.DisplayName -replace '"',"'");V=($_.DisplayVersion -replace '"',"'");D=$_.InstallDate;P=($_.Publisher -replace '"',"'")}
            })
        } catch {}

        return $r
    } # end ScanBlock

    # Deduplicate
    $seen=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $unique=[System.Collections.Generic.List[PSCustomObject]]::new(); $dupes=0
    foreach ($s in $Servers) {
        $k=if($s.ServerName){$s.ServerName.Trim()}else{''}
        if([string]::IsNullOrEmpty($k) -or $seen.Add($k)){$unique.Add($s)}else{$dupes++}
    }
    if($dupes){Write-Warning "[!] Skipped $dupes duplicate(s)."}

    $bag=[System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $portMap   = $Script:PortMap      # local copy for $using:
    $serviceMap= $ServiceMap

    if ($Script:IsPS7) {
        Write-Host "[*] PS7 ForEach-Object -Parallel (ThrottleLimit: $MaxConcurrency)" -ForegroundColor Green
        $unique | ForEach-Object -Parallel {
            $r=& $using:ScanBlock $_ $using:PingTimeoutMs $using:portMap $using:EnableWmi $using:WmiTimeoutSec $using:serviceMap
            ($using:bag).Add($r)
            $c=switch($r.HealthStatus){'Healthy'{'Green'}'Warning'{'Yellow'}'Degraded'{'DarkYellow'}'Critical'{'Red'}'DNS Failure'{'Magenta'}default{'Gray'}}
            Write-Host ("  [+] {0,-35} -> {1}" -f $r.ServerName,$r.HealthStatus) -ForegroundColor $c
        } -ThrottleLimit $MaxConcurrency
    } else {
        Write-Host "[*] PS5 Runspace pool (max: $MaxConcurrency)" -ForegroundColor Green
        $pool=[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1,$MaxConcurrency); $pool.Open()
        $jobs=[System.Collections.Generic.List[hashtable]]::new()
        foreach ($s in $unique) {
            $ps=[System.Management.Automation.PowerShell]::Create(); $ps.RunspacePool=$pool
            [void]$ps.AddScript($ScanBlock).AddArgument($s).AddArgument($PingTimeoutMs).AddArgument($portMap).AddArgument($EnableWmi).AddArgument($WmiTimeoutSec).AddArgument($serviceMap)
            $jobs.Add(@{PS=$ps;Handle=$ps.BeginInvoke();Name=$s.ServerName})
        }
        foreach ($j in $jobs) {
            try { $res=$j.PS.EndInvoke($j.Handle); foreach($item in $res){ if($null -ne $item){
                $bag.Add($item)
                $c=switch($item.HealthStatus){'Healthy'{'Green'}'Warning'{'Yellow'}'Degraded'{'DarkYellow'}'Critical'{'Red'}'DNS Failure'{'Magenta'}default{'Gray'}}
                Write-Host ("  [+] {0,-35} -> {1}" -f $item.ServerName,$item.HealthStatus) -ForegroundColor $c
            }}} catch { Write-Warning "  [!] $($j.Name): $($_.Exception.Message)" } finally { $j.PS.Dispose() }
        }
        $pool.Close(); $pool.Dispose()
    }
    Write-Host "[*] Scan done – $($bag.Count) result(s)`n" -ForegroundColor Cyan
    return [array]$bag
}
#endregion

#region ── Function: Invoke-UrlCheck ─────────────────────────────────────────
function Invoke-UrlCheck {
    [CmdletBinding()]
    param(
        [hashtable]      $UrlMap,
        [PSCustomObject[]]$ScanResults,
        [int]  $TimeoutSec    = 10,
        [int]  $WmiTimeoutSec = 15,
        [bool] $CheckPool     = $true
    )
    if (-not $UrlMap -or $UrlMap.Count -eq 0) { return @() }

    $flat=@(); foreach($app in $UrlMap.Keys){ foreach($u in $UrlMap[$app]){ $flat+=[PSCustomObject]@{App=$app;URL=$u} }}
    Write-Host "[*] URL check – $($flat.Count) URL(s)..." -ForegroundColor Cyan

    $UrlBlock = {
        param([PSCustomObject]$Item,[int]$Tms,[PSCustomObject[]]$SrvResults,[bool]$Pool,[int]$Wto)
        # Relax SSL for health checks in this runspace
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s,$c,$ch,$e) $true }
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        $r=[PSCustomObject]@{App=$Item.App;URL=$Item.URL;StatusCode=$null;ResponseMs=$null;IsHealthy=$false;Error=$null;PoolName=$null;PoolRecycle=$null}
        $sw=[System.Diagnostics.Stopwatch]::StartNew()
        try {
            $req=[System.Net.HttpWebRequest][System.Net.WebRequest]::Create($Item.URL)
            $req.Timeout=$Tms; $req.AllowAutoRedirect=$true; $req.MaximumAutomaticRedirections=5
            $req.UserAgent='SrvHealthBot/4.0'
            $resp=$req.GetResponse(); $sw.Stop()
            $r.StatusCode=[int]$resp.StatusCode; $r.ResponseMs=[int]$sw.ElapsedMilliseconds
            $r.IsHealthy=($r.StatusCode -ge 200 -and $r.StatusCode -lt 400); $resp.Close()
        } catch [System.Net.WebException] {
            $sw.Stop(); $r.ResponseMs=[int]$sw.ElapsedMilliseconds
            if($_.Exception.Response){$r.StatusCode=[int]$_.Exception.Response.StatusCode}
            $r.Error=($_.Exception.Message -replace '"',"'")
        } catch { $sw.Stop(); $r.ResponseMs=[int]$sw.ElapsedMilliseconds; $r.Error=($_.Exception.Message -replace '"',"'") }

        # IIS App Pool last recycle (only if URL is reachable)
        if ($Pool) {
            $appSrvs=@($SrvResults|Where-Object{$_.ApplicationName-eq$Item.App -and $_.ServerType-eq 'Application Server' -and $_.PingSuccess})
            foreach ($asrv in $appSrvs) {
                try { # root\WebAdministration WorkerProcess (most accurate)
                    $wp=Get-CimInstance -Namespace 'root\WebAdministration' -ClassName WorkerProcess `
                        -ComputerName $asrv.ServerName -OperationTimeoutSec $Wto -ErrorAction Stop
                    if ($wp) { $latest=$wp|Sort-Object StartTime|Select-Object -First 1
                        $r.PoolName=$latest.AppPoolName
                        $r.PoolRecycle=$latest.StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); break }
                } catch { # Fallback: earliest W3WP process creation time
                    try {
                        $w3=Get-CimInstance -ClassName Win32_Process -ComputerName $asrv.ServerName `
                            -Filter "Name='w3wp.exe'" -OperationTimeoutSec $Wto -ErrorAction Stop |
                            Sort-Object CreationDate | Select-Object -First 1
                        if ($w3) { $r.PoolRecycle=$w3.CreationDate.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'); break }
                    } catch {}
                }
            }
        }
        return $r
    }

    $bag=[System.Collections.Concurrent.ConcurrentBag[object]]::new()
    $tms=$TimeoutSec*1000; $srv=$ScanResults

    if ($Script:IsPS7) {
        $flat | ForEach-Object -Parallel {
            $r=& $using:UrlBlock $_ $using:tms $using:srv $using:CheckPool $using:WmiTimeoutSec
            ($using:bag).Add($r)
            $c=if($r.IsHealthy){'Green'}elseif($r.StatusCode){'Yellow'}else{'Red'}
            Write-Host ("  [URL] {0,-50} -> {1}" -f $r.URL,(if($r.StatusCode){"$($r.StatusCode)/$($r.ResponseMs)ms"}else{$r.Error})) -ForegroundColor $c
        } -ThrottleLimit 20
    } else {
        $pool=[System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1,20); $pool.Open()
        $jobs=[System.Collections.Generic.List[hashtable]]::new()
        foreach ($item in $flat) {
            $ps=[System.Management.Automation.PowerShell]::Create(); $ps.RunspacePool=$pool
            [void]$ps.AddScript($UrlBlock).AddArgument($item).AddArgument($tms).AddArgument($srv).AddArgument($CheckPool).AddArgument($WmiTimeoutSec)
            $jobs.Add(@{PS=$ps;Handle=$ps.BeginInvoke()})
        }
        foreach ($j in $jobs) {
            try { $res=$j.PS.EndInvoke($j.Handle); foreach($item in $res){ if($null -ne $item){ $bag.Add($item)
                $c=if($item.IsHealthy){'Green'}elseif($item.StatusCode){'Yellow'}else{'Red'}
                Write-Host ("  [URL] {0,-50} -> {1}" -f $item.URL,(if($item.StatusCode){"$($item.StatusCode)/$($item.ResponseMs)ms"}else{$item.Error})) -ForegroundColor $c
            }}} catch {} finally { $j.PS.Dispose() }
        }
        $pool.Close(); $pool.Dispose()
    }
    Write-Host "[*] URL check done – $($bag.Count) result(s)`n" -ForegroundColor Cyan
    return [array]$bag
}
#endregion


#region ── Function: ConvertTo-HtmlDashboard ─────────────────────────────────
function ConvertTo-HtmlDashboard {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][PSCustomObject[]] $ScanResults,
        [AllowEmptyCollection()][PSCustomObject[]] $UrlResults = @(),
        [Parameter(Mandatory)][string] $OutputPath
    )
    Write-Host "[*] Building HTML dashboard..." -ForegroundColor Cyan

    # ── JSON helpers ──────────────────────────────────────────────────────
    function _js([string]$s){
        if([string]::IsNullOrEmpty($s)){return ''}
        $s=$s -replace '\\','\\\\'  -replace '"','\"' -replace '`r`n','\n' -replace '`n','\n' -replace '`r','\n' -replace '`t','\t'; $s
    }
    function _num($v) { if($null -eq $v){'null'}else{[string]$v} }
    function _bool($v){ if($null -eq $v){'null'}elseif($v){'true'}else{'false'} }
    function _f($v,$d=1){ if($null -eq $v){'null'}else{[string][math]::Round($v,$d)} }
    function _jArr($items,[scriptblock]$fn){
        if(-not $items -or $items.Count -eq 0){return '[]'}
        '[' + (($items|ForEach-Object{& $fn $_}) -join ',') + ']'
    }

    $envKey = { param($n) if($Script:EnvOrder.ContainsKey($n)){$Script:EnvOrder[$n]}else{99} }

    # ── Summary stats ─────────────────────────────────────────────────────
    $total    = $ScanResults.Count
    $healthy  = @($ScanResults|Where-Object HealthStatus -eq 'Healthy').Count
    $warning  = @($ScanResults|Where-Object HealthStatus -eq 'Warning').Count
    $degraded = @($ScanResults|Where-Object HealthStatus -eq 'Degraded').Count
    $critical = @($ScanResults|Where-Object{$_.HealthStatus -in 'Critical','DNS Failure','Invalid'}).Count
    $warnDeg  = $warning + $degraded
    $online   = @($ScanResults|Where-Object{$null -ne $_.RoundTripTimeMs})
    $avgPing  = if($online.Count){[math]::Round(($online|Measure-Object RoundTripTimeMs -Average).Average,1)}else{0}
    $withCpu  = @($ScanResults|Where-Object{$null -ne $_.CpuLoadPct})
    $withMem  = @($ScanResults|Where-Object{$null -ne $_.MemUsedPct})
    $hasWmi   = ($withCpu.Count + $withMem.Count) -gt 0
    $hasWmiJs = if($hasWmi){'true'}else{'false'}
    $avgCpuJs = if($withCpu.Count){[math]::Round(($withCpu|Measure-Object CpuLoadPct -Average).Average,1),"%" -join ''}else{'N/A'}
    $avgMemJs = if($withMem.Count){[math]::Round(($withMem|Measure-Object MemUsedPct -Average).Average,1),"%" -join ''}else{'N/A'}

    # Services down count (across all servers)
    $svcsDown = @($ScanResults|ForEach-Object{$_.Svcs}|Where-Object{$_.St -eq 'Stopped'}).Count

    # URL stats
    $urlsOk   = @($UrlResults|Where-Object IsHealthy).Count
    $urlsDown = @($UrlResults|Where-Object{-not $_.IsHealthy}).Count
    $hasUrls  = $UrlResults.Count -gt 0
    $hasUrlJs = if($hasUrls){'true'}else{'false'}
    $hasSvcs  = ($Script:ServiceMap.Count -gt 0)
    $hasSvcsJs= if($hasSvcs){'true'}else{'false'}

    $genTime = Get-Date -Format 'dddd dd MMM yyyy  HH:mm:ss'
    $psVer   = $PSVersionTable.PSVersion.ToString()

    # ── Chart data ────────────────────────────────────────────────────────
    $eG   = $ScanResults|Group-Object Environment|Sort-Object{& $envKey $_.Name}
    $envL = ($eG|ForEach-Object{'"'+(_js $_.Name)+'"'}) -join ','
    $envC = ($eG|ForEach-Object{$_.Count}) -join ','

    $tG      = $online|Group-Object ServerType|Sort-Object Name
    $typeL   = ($tG|ForEach-Object{'"'+(_js $_.Name)+'"'}) -join ','
    $typeAvg = ($tG|ForEach-Object{[math]::Round(($_.Group|Measure-Object RoundTripTimeMs -Average).Average,1)}) -join ','

    $healthD = "$healthy,$warning,$degraded,$critical"

    $cpuAG   = $withCpu|Group-Object ApplicationName|Sort-Object Name
    $cpuAL   = ($cpuAG|ForEach-Object{'"'+(_js $_.Name)+'"'}) -join ','
    $cpuAD   = ($cpuAG|ForEach-Object{[math]::Round(($_.Group|Measure-Object CpuLoadPct -Average).Average,1)}) -join ','

    $memTG   = $withMem|Group-Object ServerType|Sort-Object Name
    $memTL   = ($memTG|ForEach-Object{'"'+(_js $_.Name)+'"'}) -join ','
    $memTD   = ($memTG|ForEach-Object{[math]::Round(($_.Group|Measure-Object MemUsedPct -Average).Average,1)}) -join ','

    # ── URL JSON ──────────────────────────────────────────────────────────
    $urlDataJs = _jArr $UrlResults {param($u)
        '{"app":"'+(_js $u.App)+'","url":"'+(_js $u.URL)+'","status":'+(_num $u.StatusCode)+',"ms":'+(_num $u.ResponseMs)+',"ok":'+(_bool $u.IsHealthy)+',"err":"'+(_js $u.Error)+'","pool":"'+(_js $u.PoolName)+'","recycle":"'+(_js $u.PoolRecycle)+'"}'
    }

    # ── Server/App tree JSON ──────────────────────────────────────────────
    $sb=[System.Text.StringBuilder]::new(196608)
    [void]$sb.AppendLine('[')
    $appGs=@($ScanResults|Group-Object ApplicationName|Sort-Object Name)

    for($ai=0;$ai -lt $appGs.Count;$ai++){
        $ag=$appGs[$ai]
        $aH=@($ag.Group|Where-Object{$_.HealthStatus -eq 'Healthy'}).Count
        $aW=@($ag.Group|Where-Object{$_.HealthStatus -in 'Warning','Degraded'}).Count
        $aC=@($ag.Group|Where-Object{$_.HealthStatus -in 'Critical','DNS Failure','Invalid'}).Count
        $aS=if($aC){'critical'}elseif($aW){'warning'}else{'healthy'}
        [void]$sb.AppendLine('  {"app":"'+(_js $ag.Name)+'","appStatus":"'+$aS+'","appHealthy":'+$aH+',"appWarning":'+$aW+',"appCritical":'+$aC+',')
        [void]$sb.AppendLine('  "environments":[')
        $eGs=@($ag.Group|Group-Object Environment|Sort-Object{& $envKey $_.Name})

        for($ei=0;$ei -lt $eGs.Count;$ei++){
            $eg=$eGs[$ei]
            $eH=@($eg.Group|Where-Object{$_.HealthStatus -eq 'Healthy'}).Count
            $eW=@($eg.Group|Where-Object{$_.HealthStatus -in 'Warning','Degraded'}).Count
            $eC=@($eg.Group|Where-Object{$_.HealthStatus -in 'Critical','DNS Failure','Invalid'}).Count
            $eS=if($eC){'critical'}elseif($eW){'warning'}else{'healthy'}
            [void]$sb.AppendLine('  {"env":"'+(_js $eg.Name)+'","envStatus":"'+$eS+'","envHealthy":'+$eH+',"envWarning":'+$eW+',"envCritical":'+$eC+',"servers":[')
            $sL=@($eg.Group|Sort-Object ServerType,ServerName)

            for($si=0;$si -lt $sL.Count;$si++){
                $sv=$sL[$si]; $comma=if($si -lt $sL.Count-1){','}else{''}
                $svcsJs  = _jArr $sv.Svcs    {param($s)'{"n":"'+(_js $s.N)+'","d":"'+(_js $s.D)+'","st":"'+(_js $s.St)+'","sm":"'+(_js $s.Sm)+'"}'}
                $evtsJs  = _jArr $sv.Evts    {param($e)'{"t":"'+(_js $e.T)+'","lv":"'+(_js $e.Lv)+'","src":"'+(_js $e.Src)+'","id":'+(_num $e.Id)+',"msg":"'+(_js $e.Msg)+'"}'}
                $patchJs = _jArr $sv.Patches {param($p)'{"id":"'+(_js $p.Id)+'","date":"'+(_js $p.Date)+'","desc":"'+(_js $p.Desc)+'","by":"'+(_js $p.By)+'"}'}
                $appsJs  = _jArr $sv.Apps    {param($a)'{"n":"'+(_js $a.N)+'","v":"'+(_js $a.V)+'","d":"'+(_js $a.D)+'","p":"'+(_js $a.P)+'"}'}
                [void]$sb.AppendLine('  {')
                [void]$sb.AppendLine('    "name":"'+(_js $sv.ServerName)+'","app":"'+(_js $sv.ApplicationName)+'","env":"'+(_js $sv.Environment)+'","type":"'+(_js $sv.ServerType)+'",')
                [void]$sb.AppendLine('    "csvStatus":"'+(_js $sv.Status)+'","health":"'+(_js $sv.HealthStatus)+'","ip":"'+(_js $sv.IPAddress)+'","hostname":"'+(_js $sv.HostName)+'",')
                [void]$sb.AppendLine('    "ping":'+(_num $sv.RoundTripTimeMs)+',"ttl":'+(_num $sv.TTL)+',"port":'+(_num $sv.PortChecked)+',"portOpen":'+(_bool $sv.PortOpen)+',')
                [void]$sb.AppendLine('    "cpu":'+(_num $sv.CpuLoadPct)+',"memTot":'+(_f $sv.MemTotalGB)+',"memUsed":'+(_f $sv.MemUsedGB)+',"memPct":'+(_num $sv.MemUsedPct)+',')
                [void]$sb.AppendLine('    "diskTot":'+(_f $sv.DiskTotalGB 1)+',"diskUsed":'+(_f $sv.DiskUsedGB 1)+',"diskPct":'+(_num $sv.DiskUsedPct)+',')
                [void]$sb.AppendLine('    "reboot":"'+(_js $sv.LastRebootUtc)+'","os":"'+(_js $sv.OSCaption)+'",')
                [void]$sb.AppendLine('    "error":"'+(_js $sv.ErrorMessage)+'","ts":"'+(_js $sv.ScanTimestamp)+'",')
                [void]$sb.AppendLine('    "svcs":'+$svcsJs+',"evts":'+$evtsJs+',"patches":'+$patchJs+',"apps":'+$appsJs)
                [void]$sb.AppendLine('  }'+$comma)
            }
            $eComma=if($ei -lt $eGs.Count-1){','}else{''}
            [void]$sb.AppendLine('  ]}'+$eComma)
        }
        $aComma=if($ai -lt $appGs.Count-1){','}else{''}
        [void]$sb.AppendLine('  ]}'+$aComma)
    }
    [void]$sb.AppendLine(']')
    $jsonData=$sb.ToString()

    # ══════════════════ HTML TEMPLATE ══════════════════════════════════════
    $html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Server Health Dashboard</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" crossorigin="anonymous">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" crossorigin="anonymous">
<style>
:root{--c-bg:#0b1220;--c-sf:#141e30;--c-s2:#1c2a40;--c-bd:#263348;--c-tx:#dde6f0;--c-mu:#8898aa;
  --c-ok:#34d399;--c-wn:#fbbf24;--c-dg:#fb923c;--c-er:#f87171;--c-dn:#c084fc;--c-uk:#64748b;
  --ev-dev:#60a5fa;--ev-tst:#a78bfa;--ev-rgn:#22d3ee;--ev-prd:#34d399;--ev-pdr:#fbbf24}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--c-bg);color:var(--c-tx);font-family:'Segoe UI',system-ui,sans-serif;font-size:.875rem;min-height:100vh}

/* Topbar */
.topbar{position:sticky;top:0;z-index:200;background:rgba(11,18,32,.96);border-bottom:1px solid var(--c-bd);
  backdrop-filter:blur(10px);padding:.5rem 1.25rem;display:flex;align-items:center;gap:.75rem}
.tb-brand{display:flex;align-items:center;gap:.5rem;font-weight:700;font-size:.95rem;white-space:nowrap}
.tb-brand i{color:#60a5fa;font-size:1.25rem}
.tb-nav{display:flex;gap:.2rem}
.nav-tab{background:none;border:1px solid transparent;border-radius:7px;color:var(--c-mu);
  padding:.28rem .7rem;font-size:.76rem;cursor:pointer;transition:all .15s;display:flex;align-items:center;gap:.3rem}
.nav-tab:hover{border-color:var(--c-bd);color:var(--c-tx)}
.nav-tab.active{background:rgba(96,165,250,.12);border-color:rgba(96,165,250,.35);color:#60a5fa;font-weight:600}
.tb-meta{margin-left:auto;font-size:.66rem;color:var(--c-mu);display:flex;gap:.75rem;white-space:nowrap}
.tb-meta span{display:flex;align-items:center;gap:.28rem}

/* Stat grid */
.stat-grid{display:grid;grid-template-columns:repeat(10,1fr);gap:.5rem;margin-bottom:1rem}
@media(max-width:1400px){.stat-grid{grid-template-columns:repeat(5,1fr)}}
@media(max-width:800px) {.stat-grid{grid-template-columns:repeat(3,1fr)}}
@media(max-width:500px) {.stat-grid{grid-template-columns:repeat(2,1fr)}}
.stat-card{background:var(--c-sf);border:1px solid var(--c-bd);border-radius:9px;padding:.75rem .9rem;
  position:relative;overflow:hidden;transition:transform .2s,box-shadow .2s}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:var(--ac,var(--c-mu));border-radius:9px 9px 0 0}
.stat-card:hover{transform:translateY(-2px);box-shadow:0 6px 22px rgba(0,0,0,.45)}
.sv{font-size:1.65rem;font-weight:800;line-height:1;color:var(--at,var(--c-tx))}
.sl{margin-top:.22rem;font-size:.6rem;text-transform:uppercase;letter-spacing:.09em;color:var(--c-mu)}
.si{position:absolute;right:.65rem;top:50%;transform:translateY(-50%);font-size:2rem;opacity:.08}

/* Charts */
.chart-row{display:grid;gap:.55rem;margin-bottom:.55rem}
.cr3{grid-template-columns:repeat(3,1fr)}.cr2{grid-template-columns:repeat(2,1fr)}
@media(max-width:900px){.cr3,.cr2{grid-template-columns:1fr}}
.chart-panel{background:var(--c-sf);border:1px solid var(--c-bd);border-radius:9px;padding:.85rem 1rem}
.chart-title{font-size:.6rem;text-transform:uppercase;letter-spacing:.1em;color:var(--c-mu);
  margin-bottom:.65rem;display:flex;align-items:center;gap:.35rem}

/* Toolbar */
.toolbar{display:flex;flex-wrap:wrap;align-items:center;gap:.4rem;margin-bottom:.8rem}
.sw{position:relative;flex:1;min-width:160px;max-width:320px}
.si2{position:absolute;left:.65rem;top:50%;transform:translateY(-50%);color:var(--c-mu);pointer-events:none}
.search-input{background:var(--c-sf);border:1px solid var(--c-bd);border-radius:7px;
  padding:.45rem .65rem .45rem 2rem;color:var(--c-tx);width:100%;font-size:.78rem;outline:none;transition:border-color .2s}
.search-input:focus{border-color:#60a5fa}.search-input::placeholder{color:var(--c-mu)}
.pill-group{display:flex;flex-wrap:wrap;gap:.28rem}
.fp{cursor:pointer;user-select:none;border:1px solid var(--c-bd);border-radius:18px;
  padding:.2rem .6rem;font-size:.68rem;color:var(--c-mu);transition:all .15s;display:inline-flex;align-items:center;gap:.28rem}
.fp:hover,.fp.active{border-color:#60a5fa;color:#60a5fa}.fp.active{background:rgba(96,165,250,.08);font-weight:600}
.dp2{width:6px;height:6px;border-radius:50%}
.act-grp{display:flex;gap:.28rem;margin-left:auto}
.act-btn{background:none;border:1px solid var(--c-bd);border-radius:6px;color:var(--c-mu);
  padding:.25rem .55rem;font-size:.68rem;cursor:pointer;transition:all .15s;display:inline-flex;align-items:center;gap:.25rem}
.act-btn:hover{border-color:#475569;color:var(--c-tx)}

/* App cards */
.app-list{display:flex;flex-direction:column;gap:.6rem}
.app-card{background:var(--c-sf);border:1px solid var(--c-bd);border-radius:10px;overflow:hidden;transition:box-shadow .2s}
.app-card:hover{box-shadow:0 4px 18px rgba(0,0,0,.35)}
.app-hdr{display:flex;align-items:center;gap:.55rem;padding:.72rem .9rem;cursor:pointer;user-select:none;transition:background .15s}
.app-hdr:hover{background:var(--c-s2)}.app-hdr.open{border-bottom:1px solid var(--c-bd)}
.app-icon{width:28px;height:28px;border-radius:6px;background:rgba(96,165,250,.1);border:1px solid rgba(96,165,250,.2);
  display:grid;place-items:center;flex-shrink:0;color:#60a5fa;font-size:.9rem}
.app-name{font-weight:600;font-size:.88rem;flex:1}
.app-counts{display:flex;gap:.25rem}
.cnt{font-size:.58rem;padding:.13rem .4rem;border-radius:8px;font-weight:700}
.cnt-h{background:rgba(52,211,153,.1);color:var(--c-ok);border:1px solid rgba(52,211,153,.2)}
.cnt-w{background:rgba(251,191,36,.1);color:var(--c-wn);border:1px solid rgba(251,191,36,.2)}
.cnt-c{background:rgba(248,113,113,.1);color:var(--c-er);border:1px solid rgba(248,113,113,.2)}
.app-chv{color:var(--c-mu);font-size:.74rem;transition:transform .25s}.app-chv.open{transform:rotate(90deg)}
.app-body{display:none;padding:.72rem .9rem .9rem}.app-body.show{display:block}

/* URL panel */
.url-panel{background:var(--c-s2);border:1px solid var(--c-bd);border-radius:8px;padding:.6rem .85rem;margin-bottom:.65rem}
.url-panel-hdr{font-size:.6rem;text-transform:uppercase;letter-spacing:.1em;color:var(--c-mu);
  margin-bottom:.42rem;display:flex;align-items:center;gap:.38rem}
.url-row{display:flex;align-items:center;gap:.45rem;padding:.18rem 0;font-size:.73rem;flex-wrap:wrap}
.url-sc{font-size:.61rem;padding:.1rem .35rem;border-radius:5px;font-weight:700;font-family:monospace;flex-shrink:0}
.url-ok{background:rgba(52,211,153,.1);color:var(--c-ok);border:1px solid rgba(52,211,153,.2)}
.url-fail{background:rgba(248,113,113,.1);color:var(--c-er);border:1px solid rgba(248,113,113,.2)}
.url-pend{background:rgba(100,116,139,.1);color:var(--c-uk);border:1px solid rgba(100,116,139,.2)}
.url-addr{color:#60a5fa;font-size:.74rem;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.url-ms{font-family:monospace;color:var(--c-mu);font-size:.68rem;white-space:nowrap}
.url-pool-info{font-size:.66rem;color:var(--c-mu);white-space:nowrap;display:flex;align-items:center;gap:.28rem}

/* Env blocks */
.env-block{margin-bottom:.5rem}
.env-hdr{display:flex;align-items:center;gap:.42rem;padding:.38rem .68rem;border-radius:7px;
  border:1px solid var(--c-bd);background:var(--c-s2);cursor:pointer;user-select:none;transition:border-color .15s}
.env-hdr:hover{border-color:#344156}
.env-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.env-lbl{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;flex:1}
.env-meta{font-size:.63rem;color:var(--c-mu)}
.env-chv{color:var(--c-mu);font-size:.66rem;transition:transform .22s}.env-chv.open{transform:rotate(90deg)}
.env-body{display:none;margin-top:.35rem;padding-left:.1rem}.env-body.show{display:block}
.type-div{display:flex;align-items:center;gap:.35rem;font-size:.58rem;text-transform:uppercase;
  letter-spacing:.12em;color:var(--c-mu);padding:.38rem 0 .16rem .35rem;border-left:2px solid var(--c-bd);margin:.48rem 0 .2rem}

/* Server rows */
.srv-row{display:flex;align-items:center;gap:.45rem;padding:.4rem .58rem;border-radius:7px;
  border:1px solid var(--c-bd);background:var(--c-bg);margin-bottom:.22rem;
  position:relative;transition:background .13s,border-color .13s}
.srv-row:hover{background:var(--c-s2);border-color:#344156}
.srv-row.hidden{display:none!important}
.s-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.sd-Healthy{background:var(--c-ok);box-shadow:0 0 5px var(--c-ok)}
.sd-Warning{background:var(--c-wn);box-shadow:0 0 5px var(--c-wn)}
.sd-Degraded{background:var(--c-dg);box-shadow:0 0 5px var(--c-dg)}
.sd-Critical{background:var(--c-er);box-shadow:0 0 5px var(--c-er);animation:blink 1.6s ease-in-out infinite}
.sd-DNS-Failure{background:var(--c-dn);box-shadow:0 0 5px var(--c-dn)}
.sd-Unknown,.sd-Invalid{background:var(--c-uk)}
@keyframes blink{0%,100%{box-shadow:0 0 4px var(--c-er)}50%{box-shadow:0 0 13px var(--c-er)}}
.srv-name{font-size:.8rem;font-weight:500;min-width:120px;max-width:180px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.col-ip{font-size:.7rem;font-family:monospace;color:var(--c-mu);min-width:100px}
.col-ping{font-size:.7rem;font-family:monospace;font-weight:700;min-width:58px}
.col-port{font-size:.67rem;min-width:78px}
.col-cpu,.col-mem,.col-disk{min-width:72px}
.col-reboot{font-size:.68rem;font-family:monospace;color:var(--c-mu);min-width:50px;text-align:right}
.col-badge{flex-shrink:0}
.srv-spacer{flex:1}
.port-open{color:var(--c-ok)}.port-closed{color:var(--c-er)}
.ping-fast{color:var(--c-ok)}.ping-med{color:var(--c-wn)}.ping-slow{color:var(--c-dg)}.ping-none{color:var(--c-uk)}
.mc{position:relative;display:inline-flex;align-items:center;justify-content:center;
  min-width:54px;height:18px;padding:0 .3rem;border-radius:4px;font-family:monospace;font-size:.67rem;font-weight:700;overflow:hidden}
.mc::before{content:'';position:absolute;left:0;top:0;bottom:0;width:var(--pct,0%);background:currentColor;opacity:.15}
.mc-ok{color:var(--c-ok);border:1px solid rgba(52,211,153,.2)}
.mc-wn{color:var(--c-wn);border:1px solid rgba(251,191,36,.2)}
.mc-er{color:var(--c-er);border:1px solid rgba(248,113,113,.2)}
.mc-na{color:var(--c-uk);font-size:.67rem;font-family:monospace;min-width:22px;text-align:center}
.h-badge{font-size:.58rem;padding:.12rem .4rem;border-radius:8px;text-transform:uppercase;letter-spacing:.05em;font-weight:700;white-space:nowrap;flex-shrink:0}
.hb-Healthy{background:rgba(52,211,153,.1);color:var(--c-ok);border:1px solid rgba(52,211,153,.2)}
.hb-Warning{background:rgba(251,191,36,.1);color:var(--c-wn);border:1px solid rgba(251,191,36,.2)}
.hb-Degraded{background:rgba(251,146,60,.1);color:var(--c-dg);border:1px solid rgba(251,146,60,.2)}
.hb-Critical{background:rgba(248,113,113,.1);color:var(--c-er);border:1px solid rgba(248,113,113,.2)}
.hb-DNS-Failure{background:rgba(192,132,252,.1);color:var(--c-dn);border:1px solid rgba(192,132,252,.2)}
.hb-Unknown,.hb-Invalid{background:rgba(100,116,139,.1);color:var(--c-uk);border:1px solid rgba(100,116,139,.2)}

/* Tooltip */
.tip{display:none;position:absolute;bottom:calc(100% + 6px);left:0;z-index:9999;background:var(--c-s2);
  border:1px solid var(--c-bd);border-radius:9px;padding:.5rem .78rem;min-width:260px;
  box-shadow:0 10px 28px rgba(0,0,0,.55);pointer-events:none}
.srv-row:hover .tip{display:block}
.tip table{border-collapse:collapse}
.tip td{padding:.06rem 0;vertical-align:top;font-size:.68rem}
.tip td:first-child{color:var(--c-mu);padding-right:.8rem;white-space:nowrap;font-size:.63rem;text-transform:uppercase;letter-spacing:.05em}
.tip td:last-child{font-family:monospace}
.tip-err{color:var(--c-er)!important;white-space:normal!important;font-family:sans-serif!important}
.tip-sec{color:#60a5fa!important;font-weight:700!important;font-family:sans-serif!important;
  border-top:1px solid var(--c-bd);padding-top:.3rem!important;margin-top:.15rem!important;font-size:.66rem!important}

/* Detail expand button */
.detail-btn{background:none;border:1px solid var(--c-bd);border-radius:5px;color:var(--c-mu);cursor:pointer;
  padding:.12rem .34rem;font-size:.68rem;transition:all .15s;flex-shrink:0}
.detail-btn:hover,.detail-btn.active{border-color:#60a5fa;color:#60a5fa}
.detail-btn.active i{transform:rotate(180deg)}
.detail-btn i{display:block;transition:transform .2s}

/* Detail panels */
.detail-panel{background:var(--c-sf);border:1px solid var(--c-bd);border-top:none;
  border-radius:0 0 8px 8px;margin:-.22rem 0 .24rem}
.dtab-bar{display:flex;gap:.2rem;padding:.5rem .6rem .38rem;border-bottom:1px solid var(--c-bd);flex-wrap:wrap}
.dtab{background:none;border:none;color:var(--c-mu);cursor:pointer;font-size:.68rem;
  padding:.2rem .5rem;border-radius:5px;display:flex;align-items:center;gap:.25rem;transition:all .15s}
.dtab:hover{color:var(--c-tx);background:var(--c-s2)}.dtab.active{color:#60a5fa!important;font-weight:600;background:rgba(96,165,250,.1)!important}
.dtab-content{padding:.55rem .65rem;overflow-x:auto}
.dtbl{border-collapse:collapse;width:100%;font-size:.7rem}
.dtbl th{color:var(--c-mu);font-weight:600;text-align:left;padding:.25rem .5rem;border-bottom:1px solid var(--c-bd);
  font-size:.6rem;text-transform:uppercase;letter-spacing:.08em;white-space:nowrap}
.dtbl td{padding:.25rem .5rem;border-bottom:1px solid rgba(38,51,72,.45);vertical-align:top}
.dtbl tbody tr:hover td{background:var(--c-s2)}
.dtbl .msg-cell{max-width:360px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:help}
.dtbl code{background:rgba(96,165,250,.1);color:#93c5fd;padding:.03rem .28rem;border-radius:3px;font-size:.66rem}
.dtbl a{color:#60a5fa;text-decoration:none}.dtbl a:hover{text-decoration:underline}
.svc-badge{font-size:.6rem;padding:.1rem .35rem;border-radius:7px;font-weight:700;text-transform:uppercase;white-space:nowrap}
.svc-run{background:rgba(52,211,153,.1);color:var(--c-ok);border:1px solid rgba(52,211,153,.2)}
.svc-stop{background:rgba(248,113,113,.1);color:var(--c-er);border:1px solid rgba(248,113,113,.2)}
.svc-other{background:rgba(100,116,139,.1);color:var(--c-uk);border:1px solid rgba(100,116,139,.2)}
.lv-crit{background:rgba(192,132,252,.1);color:var(--c-dn);border:1px solid rgba(192,132,252,.2);font-size:.6rem;padding:.08rem .32rem;border-radius:6px;font-weight:700}
.lv-err{background:rgba(248,113,113,.1);color:var(--c-er);border:1px solid rgba(248,113,113,.2);font-size:.6rem;padding:.08rem .32rem;border-radius:6px;font-weight:700}
.no-detail{text-align:center;padding:.85rem;color:var(--c-mu);font-size:.71rem}

/* Column visibility */
body.hide-ip .col-ip{display:none!important}
body.hide-ping .col-ping{display:none!important}
body.hide-port .col-port{display:none!important}
body.hide-cpu .col-cpu{display:none!important}
body.hide-mem .col-mem{display:none!important}
body.hide-disk .col-disk{display:none!important}
body.hide-reboot .col-reboot{display:none!important}
body.hide-badge .col-badge{display:none!important}
body.hide-url-panels .url-panel{display:none!important}
body.hide-svcs .dtab-svcs{display:none!important}
body.hide-evts .dtab-evts{display:none!important}
body.hide-patches .dtab-patches{display:none!important}
body.hide-apps-tab .dtab-apps{display:none!important}
body.compact .srv-row{padding:.26rem .48rem}
body.compact .mc{min-width:48px;height:16px;font-size:.62rem}

/* No results */
.no-results{text-align:center;padding:3rem 1rem;color:var(--c-mu)}
.no-results i{font-size:2.2rem;display:block;margin-bottom:.6rem}

/* Settings page */
#cfgPage{max-width:920px;margin:0 auto;padding:1.1rem 1.1rem 3rem}
.cfg-section-title{font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:var(--c-mu);
  margin:1.4rem 0 .6rem;display:flex;align-items:center;gap:.4rem}
.cfg-card{background:var(--c-sf);border:1px solid var(--c-bd);border-radius:9px;padding:1rem 1.15rem;margin-bottom:.65rem}
.cfg-card-hdr{font-weight:600;font-size:.82rem;margin-bottom:.22rem;display:flex;align-items:center;gap:.4rem}
.cfg-card-hdr i{color:#60a5fa}
.cfg-card-desc{font-size:.7rem;color:var(--c-mu);margin-bottom:.8rem}
.tog-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(185px,1fr));gap:.48rem .75rem}
.tog{display:flex;align-items:center;gap:.5rem;cursor:pointer;user-select:none;font-size:.78rem;padding:.08rem 0}
.tog input[type="checkbox"]{display:none}
.tog-track{width:34px;height:18px;background:var(--c-bd);border-radius:9px;position:relative;transition:background .2s;flex-shrink:0}
.tog input:checked+.tog-track{background:#60a5fa}
.tog-thumb{position:absolute;top:2px;left:2px;width:14px;height:14px;background:white;border-radius:50%;transition:left .18s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.tog input:checked+.tog-track .tog-thumb{left:18px}
.tog-disabled{opacity:.4;pointer-events:none}
.thr-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:.55rem .75rem}
.thr-row{display:flex;align-items:center;gap:.45rem;font-size:.76rem;margin-top:.28rem}
.thr-lbl{min-width:95px;color:var(--c-mu);font-size:.7rem}
.thr-in{background:var(--c-bg);border:1px solid var(--c-bd);border-radius:5px;color:var(--c-tx);
  padding:.2rem .42rem;width:60px;font-family:monospace;font-size:.76rem;text-align:center;outline:none;transition:border-color .2s}
.thr-in:focus{border-color:#60a5fa}
.cfg-note{background:rgba(96,165,250,.06);border:1px solid rgba(96,165,250,.2);border-radius:7px;
  padding:.6rem .85rem;font-size:.73rem;color:#7eb8f7;display:flex;align-items:flex-start;gap:.5rem;margin-bottom:.6rem}
.cfg-note i{flex-shrink:0;margin-top:.05rem}
.cfg-footer{display:flex;justify-content:flex-end;margin-top:1.4rem}
.cfg-btn-reset{background:none;border:1px solid rgba(248,113,113,.4);border-radius:7px;color:var(--c-er);
  padding:.35rem .85rem;font-size:.76rem;cursor:pointer;transition:all .15s;display:flex;align-items:center;gap:.35rem}
.cfg-btn-reset:hover{background:rgba(248,113,113,.07);border-color:var(--c-er)}
@media(max-width:600px){.tog-grid{grid-template-columns:1fr 1fr}.thr-grid{grid-template-columns:1fr}}
</style>
</head>
<body>

<!-- TOPBAR -->
<header class="topbar">
  <div class="tb-brand"><i class="bi bi-hdd-rack-fill"></i>Server Health Dashboard</div>
  <nav class="tb-nav">
    <button id="navDash" class="nav-tab active" onclick="showPage('dash')"><i class="bi bi-speedometer2"></i>Dashboard</button>
    <button id="navCfg"  class="nav-tab"        onclick="showPage('cfg')"><i class="bi bi-gear-fill"></i>Settings</button>
  </nav>
  <div class="tb-meta">
    <span><i class="bi bi-clock-history"></i>%%GEN_TIME%%</span>
    <span><i class="bi bi-terminal"></i>PS %%PS_VER%%</span>
  </div>
</header>

<!-- DASHBOARD PAGE -->
<div id="dashPage" style="max-width:1700px;margin:0 auto;padding:1rem 1rem 3rem">

  <!-- Stat cards -->
  <div class="stat-grid">
    <div class="stat-card" style="--ac:#60a5fa;--at:#60a5fa"><div class="sv">%%TOTAL%%</div><div class="sl">Total Servers</div><i class="bi bi-hdd-stack si"></i></div>
    <div class="stat-card" style="--ac:var(--c-ok);--at:var(--c-ok)"><div class="sv">%%HEALTHY%%</div><div class="sl">Healthy</div><i class="bi bi-check-circle si"></i></div>
    <div class="stat-card" style="--ac:var(--c-wn);--at:var(--c-wn)"><div class="sv">%%WARN_DEG%%</div><div class="sl">Warn / Degraded</div><i class="bi bi-exclamation-triangle si"></i></div>
    <div class="stat-card" style="--ac:var(--c-er);--at:var(--c-er)"><div class="sv">%%CRITICAL%%</div><div class="sl">Critical / Offline</div><i class="bi bi-x-circle si"></i></div>
    <div class="stat-card" style="--ac:#a78bfa;--at:#a78bfa"><div class="sv">%%AVG_PING%%ms</div><div class="sl">Avg Ping</div><i class="bi bi-activity si"></i></div>
    <div class="stat-card" style="--ac:var(--c-ok);--at:var(--c-ok)"><div class="sv">%%AVG_CPU%%</div><div class="sl">Avg CPU Load</div><i class="bi bi-cpu si"></i></div>
    <div class="stat-card" style="--ac:#22d3ee;--at:#22d3ee"><div class="sv">%%AVG_MEM%%</div><div class="sl">Avg Memory</div><i class="bi bi-memory si"></i></div>
    <div class="stat-card" style="--ac:var(--c-ok);--at:var(--c-ok)" id="scUrlOk"><div class="sv">%%URLS_OK%%</div><div class="sl">URLs Healthy</div><i class="bi bi-link-45deg si"></i></div>
    <div class="stat-card" style="--ac:var(--c-er);--at:var(--c-er)" id="scUrlDown"><div class="sv">%%URLS_DOWN%%</div><div class="sl">URLs Down</div><i class="bi bi-link-break si"></i></div>
    <div class="stat-card" style="--ac:#38bdf8;--at:#38bdf8"><div class="sv" id="visCount">%%TOTAL%%</div><div class="sl">Showing (filtered)</div><i class="bi bi-funnel si"></i></div>
  </div>

  <!-- Charts row 1 -->
  <div class="chart-row cr3" id="chartRow1">
    <div class="chart-panel" id="cpEnv"><div class="chart-title"><i class="bi bi-pie-chart-fill"></i>By Environment</div><div style="position:relative;height:195px"><canvas id="chartEnv"></canvas></div></div>
    <div class="chart-panel" id="cpType"><div class="chart-title"><i class="bi bi-bar-chart-line-fill"></i>Avg Ping by Server Type (ms)</div><div style="position:relative;height:195px"><canvas id="chartType"></canvas></div></div>
    <div class="chart-panel" id="cpHealth"><div class="chart-title"><i class="bi bi-clipboard2-pulse-fill"></i>Health Distribution</div><div style="position:relative;height:195px"><canvas id="chartHealth"></canvas></div></div>
  </div>

  <!-- Charts row 2 (WMI) -->
  <div class="chart-row cr2" id="chartRow2" style="display:none">
    <div class="chart-panel" id="cpCpu"><div class="chart-title"><i class="bi bi-cpu-fill"></i>Avg CPU % by Application</div><div style="position:relative;height:195px"><canvas id="chartCpu"></canvas></div></div>
    <div class="chart-panel" id="cpMem"><div class="chart-title"><i class="bi bi-memory"></i>Avg Memory % by Server Type</div><div style="position:relative;height:195px"><canvas id="chartMem"></canvas></div></div>
  </div>

  <!-- Toolbar -->
  <div class="toolbar">
    <div class="sw"><i class="bi bi-search si2"></i><input type="text" id="searchBox" class="search-input" placeholder="Search name or IP…" oninput="applyFilters()"></div>
    <div class="pill-group">
      <span class="fp active" onclick="setFilter(this,'all')">All</span>
      <span class="fp" onclick="setFilter(this,'Healthy')"><span class="dp2" style="background:var(--c-ok)"></span>Healthy</span>
      <span class="fp" onclick="setFilter(this,'Warning')"><span class="dp2" style="background:var(--c-wn)"></span>Warning</span>
      <span class="fp" onclick="setFilter(this,'Degraded')"><span class="dp2" style="background:var(--c-dg)"></span>Degraded</span>
      <span class="fp" onclick="setFilter(this,'Critical')"><span class="dp2" style="background:var(--c-er)"></span>Critical</span>
      <span class="fp" onclick="setFilter(this,'DNS Failure')"><span class="dp2" style="background:var(--c-dn)"></span>DNS Fail</span>
    </div>
    <div class="act-grp">
      <button class="act-btn" onclick="expandAll()"><i class="bi bi-arrows-expand"></i>Expand All</button>
      <button class="act-btn" onclick="collapseAll()"><i class="bi bi-arrows-collapse"></i>Collapse</button>
      <button class="act-btn" onclick="exportCsv()"><i class="bi bi-download"></i>Export CSV</button>
    </div>
  </div>

  <div id="appTree" class="app-list"></div>
  <div id="noResults" class="no-results" style="display:none"><i class="bi bi-search"></i>No servers match the current filter.</div>
</div>

<!-- SETTINGS PAGE -->
<div id="cfgPage" style="display:none">
  <p class="cfg-section-title" style="margin-top:1.1rem"><i class="bi bi-gear-fill"></i>Dashboard Configuration<span style="margin-left:auto;font-size:.63rem">Settings persist in browser storage</span></p>

  <div class="cfg-note" id="cfgNoWmi" style="display:none"><i class="bi bi-info-circle-fill"></i>
    <span>CPU, Memory, Disk, Services, Event Log, and Installed Apps data unavailable.
    Re-run without <code style="background:rgba(255,255,255,.07);padding:.03rem .28rem;border-radius:3px">-SkipSystemMetrics</code> and ensure WinRM access to targets.</span></div>

  <div class="cfg-card">
    <div class="cfg-card-hdr"><i class="bi bi-table"></i>Server Row Columns</div>
    <div class="cfg-card-desc">Toggle individual data columns in the server list.</div>
    <div class="tog-grid">
      <label class="tog"><input type="checkbox" id="cfg-showIp"     onchange="applyS('showIp',    this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>IP Address</label>
      <label class="tog"><input type="checkbox" id="cfg-showPing"   onchange="applyS('showPing',  this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Ping (ms)</label>
      <label class="tog"><input type="checkbox" id="cfg-showPort"   onchange="applyS('showPort',  this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Port Status</label>
      <label class="tog" id="tog-cpu"><input type="checkbox" id="cfg-showCpu" onchange="applyS('showCpu',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>CPU Load %</label>
      <label class="tog" id="tog-mem"><input type="checkbox" id="cfg-showMem" onchange="applyS('showMem',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Memory Usage</label>
      <label class="tog" id="tog-disk"><input type="checkbox" id="cfg-showDisk" onchange="applyS('showDisk',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Disk Usage (C:)</label>
      <label class="tog" id="tog-reboot"><input type="checkbox" id="cfg-showReboot" onchange="applyS('showReboot',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Last Reboot</label>
      <label class="tog"><input type="checkbox" id="cfg-showBadge" onchange="applyS('showBadge', this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Health Badge</label>
    </div>
  </div>

  <div class="cfg-card">
    <div class="cfg-card-hdr"><i class="bi bi-card-list"></i>Server Detail Panels</div>
    <div class="cfg-card-desc">Control which tabs appear in each server's expandable detail section.</div>
    <div class="tog-grid">
      <label class="tog"><input type="checkbox" id="cfg-showUrlPanel" onchange="applyS('showUrlPanel',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>URL Health</label>
      <label class="tog" id="tog-svcs"><input type="checkbox" id="cfg-showSvcs" onchange="applyS('showSvcs',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Windows Services</label>
      <label class="tog" id="tog-evts"><input type="checkbox" id="cfg-showEvts" onchange="applyS('showEvts',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Event Logs</label>
      <label class="tog" id="tog-patches"><input type="checkbox" id="cfg-showPatches" onchange="applyS('showPatches',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Security Patches</label>
      <label class="tog" id="tog-apps"><input type="checkbox" id="cfg-showApps" onchange="applyS('showApps',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Installed Apps</label>
    </div>
  </div>

  <div class="cfg-card">
    <div class="cfg-card-hdr"><i class="bi bi-bar-chart-fill"></i>Charts</div>
    <div class="cfg-card-desc">Show or hide individual chart panels.</div>
    <div class="tog-grid">
      <label class="tog"><input type="checkbox" id="cfg-chartEnv"    onchange="applyS('chartEnv',   this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Environment Pie</label>
      <label class="tog"><input type="checkbox" id="cfg-chartType"   onchange="applyS('chartType',  this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Avg Ping by Type</label>
      <label class="tog"><input type="checkbox" id="cfg-chartHealth" onchange="applyS('chartHealth',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Health Distribution</label>
      <label class="tog" id="tog-chartCpu"><input type="checkbox" id="cfg-chartCpu" onchange="applyS('chartCpu',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>CPU by Application</label>
      <label class="tog" id="tog-chartMem"><input type="checkbox" id="cfg-chartMem" onchange="applyS('chartMem',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Memory by Type</label>
    </div>
  </div>

  <div class="cfg-card">
    <div class="cfg-card-hdr"><i class="bi bi-sliders"></i>Health Thresholds</div>
    <div class="cfg-card-desc">Colour boundaries for metric classification. Changes take effect immediately.</div>
    <div class="thr-grid">
      <div><div style="font-size:.67rem;color:var(--c-mu);font-weight:600;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.38rem"><i class="bi bi-activity me-1"></i>Ping (ms)</div>
        <div class="thr-row"><span class="thr-lbl">Warning above</span><input class="thr-in" type="number" id="thr-pingWarn" onchange="applyT('pingWarn',+this.value)"><span style="font-size:.68rem;color:var(--c-mu)">ms</span></div>
        <div class="thr-row"><span class="thr-lbl">Degraded above</span><input class="thr-in" type="number" id="thr-pingCrit" onchange="applyT('pingCrit',+this.value)"><span style="font-size:.68rem;color:var(--c-mu)">ms</span></div></div>
      <div><div style="font-size:.67rem;color:var(--c-mu);font-weight:600;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.38rem"><i class="bi bi-cpu me-1"></i>CPU (%)</div>
        <div class="thr-row"><span class="thr-lbl">Warning above</span><input class="thr-in" type="number" id="thr-cpuWarn" onchange="applyT('cpuWarn',+this.value)"><span style="font-size:.68rem;color:var(--c-mu)">%</span></div>
        <div class="thr-row"><span class="thr-lbl">Critical above</span><input class="thr-in" type="number" id="thr-cpuCrit" onchange="applyT('cpuCrit',+this.value)"><span style="font-size:.68rem;color:var(--c-mu)">%</span></div></div>
      <div><div style="font-size:.67rem;color:var(--c-mu);font-weight:600;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.38rem"><i class="bi bi-memory me-1"></i>Memory (%)</div>
        <div class="thr-row"><span class="thr-lbl">Warning above</span><input class="thr-in" type="number" id="thr-memWarn" onchange="applyT('memWarn',+this.value)"><span style="font-size:.68rem;color:var(--c-mu)">%</span></div>
        <div class="thr-row"><span class="thr-lbl">Critical above</span><input class="thr-in" type="number" id="thr-memCrit" onchange="applyT('memCrit',+this.value)"><span style="font-size:.68rem;color:var(--c-mu)">%</span></div></div>
      <div><div style="font-size:.67rem;color:var(--c-mu);font-weight:600;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.38rem"><i class="bi bi-device-hdd me-1"></i>Disk (%)</div>
        <div class="thr-row"><span class="thr-lbl">Warning above</span><input class="thr-in" type="number" id="thr-diskWarn" onchange="applyT('diskWarn',+this.value)"><span style="font-size:.68rem;color:var(--c-mu)">%</span></div>
        <div class="thr-row"><span class="thr-lbl">Critical above</span><input class="thr-in" type="number" id="thr-diskCrit" onchange="applyT('diskCrit',+this.value)"><span style="font-size:.68rem;color:var(--c-mu)">%</span></div></div>
    </div>
  </div>

  <div class="cfg-card">
    <div class="cfg-card-hdr"><i class="bi bi-toggles"></i>Behaviour</div>
    <div class="cfg-card-desc">General display and interaction preferences.</div>
    <div class="tog-grid">
      <label class="tog"><input type="checkbox" id="cfg-autoExpand"   onchange="applyS('autoExpand',  this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Auto-expand all on load</label>
      <label class="tog"><input type="checkbox" id="cfg-showArchived" onchange="applyS('showArchived',this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Show Archived Servers</label>
      <label class="tog"><input type="checkbox" id="cfg-compactMode"  onchange="applyS('compactMode', this.checked)"><span class="tog-track"><span class="tog-thumb"></span></span>Compact Mode</label>
    </div>
  </div>
  <div class="cfg-footer"><button class="cfg-btn-reset" onclick="resetSettings()"><i class="bi bi-arrow-counterclockwise"></i>Reset to Defaults</button></div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js" crossorigin="anonymous"></script>
<script>
(function(){
'use strict';

/* ── Data ── */
var DATA     = %%JSON_DATA%%;
var URL_DATA = %%URL_DATA%%;
var HAS_WMI  = %%HAS_WMI%%;
var HAS_URLS = %%HAS_URLS%%;
var HAS_SVCS = %%HAS_SVCS%%;
var ENV_HEX  = {DEV:'#60a5fa',TEST:'#a78bfa',REGN:'#22d3ee',PROD:'#34d399','PROD-DR':'#fbbf24'};
var PAL      = ['#60a5fa','#a78bfa','#34d399','#fb923c','#f87171','#38bdf8','#fbbf24','#e879f9'];

var urlsByApp = {};
URL_DATA.forEach(function(u){ if(!urlsByApp[u.app])urlsByApp[u.app]=[]; urlsByApp[u.app].push(u); });

/* ── Settings ── */
var DEFAULTS = {
  showIp:true,showPing:true,showPort:true,showCpu:true,showMem:true,showDisk:true,showReboot:true,showBadge:true,
  showUrlPanel:true,showSvcs:true,showEvts:true,showPatches:true,showApps:true,
  chartEnv:true,chartType:true,chartHealth:true,chartCpu:true,chartMem:true,
  pingWarn:50,pingCrit:200,cpuWarn:70,cpuCrit:90,memWarn:80,memCrit:95,diskWarn:75,diskCrit:90,
  autoExpand:false,showArchived:true,compactMode:false
};
var S=Object.assign({},DEFAULTS);

function loadSettings(){ try{ var r=localStorage.getItem('srvDash4'); if(r)S=Object.assign({},DEFAULTS,JSON.parse(r)); }catch(e){} }
function saveSettings(){ try{ localStorage.setItem('srvDash4',JSON.stringify(S)); }catch(e){} }
window.applyS=function(k,v){ S[k]=v; saveSettings(); applyAllSettings(); };
window.applyT=function(k,v){ S[k]=v; saveSettings(); recolorMetrics(); };
window.resetSettings=function(){ S=Object.assign({},DEFAULTS); saveSettings(); syncCfgUI(); applyAllSettings(); };

function applyAllSettings(){
  var b=document.body;
  b.classList.toggle('hide-ip',    !S.showIp);
  b.classList.toggle('hide-ping',  !S.showPing);
  b.classList.toggle('hide-port',  !S.showPort);
  b.classList.toggle('hide-cpu',   !S.showCpu);
  b.classList.toggle('hide-mem',   !S.showMem);
  b.classList.toggle('hide-disk',  !S.showDisk);
  b.classList.toggle('hide-reboot',!S.showReboot);
  b.classList.toggle('hide-badge', !S.showBadge);
  b.classList.toggle('hide-url-panels',!S.showUrlPanel);
  b.classList.toggle('hide-svcs',  !S.showSvcs);
  b.classList.toggle('hide-evts',  !S.showEvts);
  b.classList.toggle('hide-patches',!S.showPatches);
  b.classList.toggle('hide-apps-tab',!S.showApps);
  b.classList.toggle('compact',    S.compactMode);
  ['cpEnv','cpType','cpHealth'].forEach(function(id,i){ showPanel(id,[S.chartEnv,S.chartType,S.chartHealth][i]); });
  showPanel('cpCpu',S.chartCpu&&HAS_WMI); showPanel('cpMem',S.chartMem&&HAS_WMI);
  var r2=document.getElementById('chartRow2'); if(r2) r2.style.display=HAS_WMI&&(S.chartCpu||S.chartMem)?'':'none';
  applyFilters();
}
function showPanel(id,v){ var e=document.getElementById(id); if(e) e.style.display=v?'':'none'; }

function syncCfgUI(){
  ['showIp','showPing','showPort','showCpu','showMem','showDisk','showReboot','showBadge',
   'showUrlPanel','showSvcs','showEvts','showPatches','showApps',
   'chartEnv','chartType','chartHealth','chartCpu','chartMem','autoExpand','showArchived','compactMode'].forEach(function(k){
    var e=document.getElementById('cfg-'+k); if(e) e.checked=S[k]; });
  ['pingWarn','pingCrit','cpuWarn','cpuCrit','memWarn','memCrit','diskWarn','diskCrit'].forEach(function(k){
    var e=document.getElementById('thr-'+k); if(e) e.value=S[k]; });
  if(!HAS_WMI){
    ['tog-cpu','tog-mem','tog-disk','tog-reboot','tog-svcs','tog-evts','tog-patches','tog-apps','tog-chartCpu','tog-chartMem'].forEach(function(id){
      var e=document.getElementById(id); if(e) e.classList.add('tog-disabled'); });
    var n=document.getElementById('cfgNoWmi'); if(n) n.style.display='';
  }
  if(!HAS_URLS){
    var su=document.getElementById('scUrlOk'),sd=document.getElementById('scUrlDown');
    if(su) su.style.opacity='.4'; if(sd) sd.style.opacity='.4';
  }
}

/* ── Page nav ── */
window.showPage=function(p){
  document.getElementById('dashPage').style.display=p==='dash'?'':'none';
  document.getElementById('cfgPage').style.display=p==='cfg'?'':'none';
  document.getElementById('navDash').classList.toggle('active',p==='dash');
  document.getElementById('navCfg').classList.toggle('active',p==='cfg');
  if(p==='cfg') syncCfgUI();
};

/* ── Utils ── */
function esc(s){ if(!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function pingCls(ms){ if(ms===null||ms===undefined) return 'ping-none'; return ms>=S.pingCrit?'ping-slow':ms>=S.pingWarn?'ping-med':'ping-fast'; }
function metCls(p,w,c){ if(p===null||p===undefined||isNaN(p)) return ''; return p>=c?'mc-er':p>=w?'mc-wn':'mc-ok'; }
function metCell(p,w,c,lbl){
  if(p===null||p===undefined) return '<span class="mc-na">—</span>';
  var l=lbl!==undefined&&lbl!==null?lbl:p+'%';
  return '<span class="mc '+metCls(p,w,c)+'" style="--pct:'+Math.min(p,100)+'%">'+esc(l)+'</span>';
}
function sanitizeId(s){ return (s||'').replace(/[^a-zA-Z0-9]/g,'_'); }
function rebootAge(iso){
  if(!iso) return '—';
  var d=new Date(iso); if(isNaN(d.getTime())) return '—';
  var m=Math.floor((Date.now()-d.getTime())/60000);
  if(m<1) return 'now'; if(m<60) return m+'m'; if(m<1440) return Math.floor(m/60)+'h'; return Math.floor(m/1440)+'d';
}
function rebootFull(iso){ if(!iso) return '—'; var d=new Date(iso); return isNaN(d.getTime())?'—':d.toLocaleString(); }
function dotCls(h)  { return 'sd-'  +String(h).replace(/\s/g,'-'); }
function badgeCls(h){ return 'hb-'  +String(h).replace(/\s/g,'-'); }
function typeIcon(t){ t=(t||'').toLowerCase(); return t.indexOf('database')>=0?'database-fill':t.indexOf('etl')>=0?'arrow-left-right':t.indexOf('file')>=0?'folder2-open':'display'; }

/* ── URL panel ── */
function buildUrlPanel(urls){
  if(!urls||!urls.length) return null;
  var div=document.createElement('div'); div.className='url-panel';
  var h='<div class="url-panel-hdr"><i class="bi bi-link-45deg"></i>URL Health</div>';
  urls.forEach(function(u){
    var scCls=u.ok?'url-ok':(u.status?'url-fail':'url-pend');
    var scTxt=u.status!==null&&u.status!==undefined?String(u.status):(u.err?'ERR':'—');
    var msTxt=u.ms!==null&&u.ms!==undefined?u.ms+'ms':'—';
    var poolH='';
    if(u.pool||u.recycle) poolH='<span class="url-pool-info"><i class="bi bi-recycle"></i>'+(u.pool?esc(u.pool)+' · ':'')+rebootAge(u.recycle)+'</span>';
    var errH=u.err?'<span style="font-size:.65rem;color:var(--c-er);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:160px" title="'+esc(u.err)+'">'+esc(u.err)+'</span>':'';
    h+='<div class="url-row"><span class="url-sc '+scCls+'">'+scTxt+'</span><span class="url-addr" title="'+esc(u.url)+'">'+esc(u.url)+'</span><span class="url-ms">'+msTxt+'</span>'+errH+poolH+'</div>';
  });
  div.innerHTML=h; return div;
}

/* ── Detail table builders ── */
function buildSvcsTable(s){
  if(!s||!s.length) return '<div class="no-detail">No services monitored for this application</div>';
  var h='<table class="dtbl"><thead><tr><th>Service</th><th>Display Name</th><th>Status</th><th>Start Mode</th></tr></thead><tbody>';
  s.forEach(function(r){ var bc=r.st==='Running'?'svc-run':r.st==='Stopped'?'svc-stop':'svc-other';
    h+='<tr><td><code>'+esc(r.n)+'</code></td><td>'+esc(r.d)+'</td><td><span class="svc-badge '+bc+'">'+esc(r.st)+'</span></td><td>'+esc(r.sm)+'</td></tr>'; });
  return h+'</tbody></table>';
}
function buildEvtsTable(e){
  if(!e||!e.length) return '<div class="no-detail">No recent Critical/Error events found</div>';
  var h='<table class="dtbl"><thead><tr><th>Time</th><th>Level</th><th>Source</th><th>ID</th><th>Message</th></tr></thead><tbody>';
  e.forEach(function(r){ var bc=r.lv==='Critical'?'lv-crit':'lv-err';
    h+='<tr><td style="white-space:nowrap">'+esc(r.t)+'</td><td><span class="'+bc+'">'+esc(r.lv)+'</span></td><td>'+esc(r.src)+'</td><td>'+r.id+'</td><td class="msg-cell" title="'+esc(r.msg)+'">'+esc(r.msg)+'</td></tr>'; });
  return h+'</tbody></table>';
}
function buildPatchTable(p){
  if(!p||!p.length) return '<div class="no-detail">No hotfix data collected</div>';
  var h='<table class="dtbl"><thead><tr><th>KB ID</th><th>Installed</th><th>Description</th><th>Installed By</th></tr></thead><tbody>';
  p.forEach(function(r){ var kn=r.id?r.id.replace('KB',''):'';
    var lnk=kn?'<a href="https://support.microsoft.com/kb/'+kn+'" target="_blank">'+esc(r.id)+'</a>':esc(r.id);
    h+='<tr><td>'+lnk+'</td><td style="white-space:nowrap">'+esc(r.date)+'</td><td>'+esc(r.desc)+'</td><td>'+esc(r.by)+'</td></tr>'; });
  return h+'</tbody></table>';
}
function buildAppsTable(a){
  if(!a||!a.length) return '<div class="no-detail">No installed app data collected</div>';
  var h='<table class="dtbl"><thead><tr><th>Application</th><th>Version</th><th>Install Date</th><th>Publisher</th></tr></thead><tbody>';
  a.forEach(function(r){ var df=r.d&&r.d.match&&r.d.match(/^\d{8}$/)? r.d.slice(0,4)+'-'+r.d.slice(4,6)+'-'+r.d.slice(6,8):(r.d||'—');
    h+='<tr><td>'+esc(r.n)+'</td><td><code>'+esc(r.v||'—')+'</code></td><td style="white-space:nowrap">'+df+'</td><td>'+esc(r.p||'—')+'</td></tr>'; });
  return h+'</tbody></table>';
}

/* ── Detail panel ── */
function buildDetailPanel(srv){
  var sid=sanitizeId(srv.name);
  var panel=document.createElement('div'); panel.id='dp-'+sid; panel.className='detail-panel'; panel.style.display='none';
  var tabs=[];
  if(srv.svcs   &&srv.svcs.length)    tabs.push({id:'svcs',   cls:'dtab-svcs',    icon:'gear-fill',               lbl:'Services ('+srv.svcs.length+')',   fn:function(){return buildSvcsTable(srv.svcs);}});
  if(srv.evts   &&srv.evts.length)    tabs.push({id:'evts',   cls:'dtab-evts',    icon:'exclamation-triangle-fill',lbl:'Events ('+srv.evts.length+')',     fn:function(){return buildEvtsTable(srv.evts);}});
  if(srv.patches&&srv.patches.length) tabs.push({id:'patches',cls:'dtab-patches', icon:'shield-check',            lbl:'Patches ('+srv.patches.length+')', fn:function(){return buildPatchTable(srv.patches);}});
  if(srv.apps   &&srv.apps.length)    tabs.push({id:'apps',   cls:'dtab-apps',    icon:'box-seam',                lbl:'Apps ('+srv.apps.length+')',       fn:function(){return buildAppsTable(srv.apps);}});
  if(!tabs.length){ panel.innerHTML='<div class="no-detail"><i class="bi bi-info-circle"></i> No detail data — enable WMI or check connectivity</div>'; return panel; }
  var tbH='<div class="dtab-bar">',ctH='<div class="dtab-content">';
  tabs.forEach(function(t,i){
    tbH+='<button id="dtt-'+sid+'-'+t.id+'" class="dtab '+t.cls+(i===0?' active':'')+'" onclick="showDTab(\''+sid+'\',\''+t.id+'\')"><i class="bi bi-'+t.icon+'"></i> '+t.lbl+'</button>';
    ctH+='<div id="dtc-'+sid+'-'+t.id+'" class="dtab-pane"'+(i===0?'':' style="display:none"')+'>'+t.fn()+'</div>';
  });
  panel.innerHTML=tbH+'</div>'+ctH+'</div>'; return panel;
}

/* ── Build tree ── */
function buildTree(){
  var tree=document.getElementById('appTree'); tree.innerHTML='';
  DATA.forEach(function(app,ai){
    var pills='';
    if(app.appHealthy)  pills+='<span class="cnt cnt-h"><i class="bi bi-check2"></i> '+app.appHealthy+'</span>';
    if(app.appWarning)  pills+='<span class="cnt cnt-w"><i class="bi bi-dash"></i> '+app.appWarning+'</span>';
    if(app.appCritical) pills+='<span class="cnt cnt-c"><i class="bi bi-x"></i> '+app.appCritical+'</span>';
    var em=app.appStatus==='critical'?'🔴':app.appStatus==='warning'?'🟡':'🟢';
    var card=document.createElement('div'); card.className='app-card';
    card.innerHTML='<div class="app-hdr" id="ah-'+ai+'" onclick="togApp('+ai+')">'
      +'<div class="app-icon"><i class="bi bi-grid-3x3-gap-fill"></i></div>'
      +'<span class="app-name">'+esc(app.app)+'</span>'
      +'<div class="app-counts">'+pills+'</div>'
      +'<span style="font-size:.8rem">'+em+'</span>'
      +'<i class="bi bi-chevron-right app-chv" id="ac-'+ai+'"></i>'
      +'</div><div class="app-body" id="ab-'+ai+'"></div>';
    var body=card.querySelector('.app-body');

    // URL health panel at application level
    if(urlsByApp[app.app]){
      var up=buildUrlPanel(urlsByApp[app.app]); if(up) body.appendChild(up);
    }

    app.environments.forEach(function(env,ei){
      var ec=ENV_HEX[env.env]||'var(--c-mu)';
      var pvs=env.servers.filter(function(s){return s.ping!==null&&s.ping!==undefined;}).map(function(s){return s.ping;});
      var avgP=pvs.length?Math.round(pvs.reduce(function(a,b){return a+b;},0)/pvs.length):null;
      var meta=env.servers.length+' server'+(env.servers.length!==1?'s':'')+(avgP!==null?' · avg '+avgP+'ms':'');
      var cBadge=env.envCritical?'<span class="cnt cnt-c" style="font-size:.56rem">'+env.envCritical+' ✗</span>':'';
      var envDiv=document.createElement('div'); envDiv.className='env-block';
      envDiv.innerHTML='<div class="env-hdr" onclick="togEnv('+ai+','+ei+')">'
        +'<span class="env-dot" style="background:'+ec+'"></span>'
        +'<span class="env-lbl" style="color:'+ec+'">'+esc(env.env)+'</span>'
        +'<span class="env-meta">'+meta+'</span>'+cBadge
        +'<i class="bi bi-chevron-right env-chv" id="ec-'+ai+'-'+ei+'"></i>'
        +'</div><div class="env-body" id="eb-'+ai+'-'+ei+'"></div>';
      var eBody=envDiv.querySelector('.env-body');
      var byType={};
      env.servers.forEach(function(s){ if(!byType[s.type])byType[s.type]=[]; byType[s.type].push(s); });
      Object.keys(byType).sort().forEach(function(t){
        var td=document.createElement('div'); td.className='type-div';
        td.innerHTML='<i class="bi bi-'+typeIcon(t)+'"></i>'+esc(t); eBody.appendChild(td);
        byType[t].forEach(function(srv){
          eBody.appendChild(buildRow(srv));
          eBody.appendChild(buildDetailPanel(srv));
        });
      });
      body.appendChild(envDiv);
    });
    tree.appendChild(card);
    if(S.autoExpand) togApp(ai);
  });
}

/* ── Server row ── */
function buildRow(srv){
  var sid=sanitizeId(srv.name);
  var row=document.createElement('div'); row.className='srv-row';
  row.setAttribute('data-health', srv.health||'');
  row.setAttribute('data-name',  (srv.name||'').toLowerCase());
  row.setAttribute('data-ip',    (srv.ip||'').toLowerCase());
  row.setAttribute('data-csvstatus', srv.csvStatus||'');
  row.setAttribute('data-ms',   srv.ping!==null&&srv.ping!==undefined?srv.ping:'');
  row.setAttribute('data-cpu',  srv.cpu!==null&&srv.cpu!==undefined?srv.cpu:'');
  row.setAttribute('data-mem',  srv.memPct!==null&&srv.memPct!==undefined?srv.memPct:'');
  row.setAttribute('data-disk', srv.diskPct!==null&&srv.diskPct!==undefined?srv.diskPct:'');

  var ptx=srv.ping!==null&&srv.ping!==undefined?srv.ping+'ms':'N/A';
  var phH=srv.port!==null&&srv.port!==undefined?(srv.portOpen?'<span class="port-open"><i class="bi bi-check2-circle"></i> :'+srv.port+'</span>':'<span class="port-closed"><i class="bi bi-x-circle"></i> :'+srv.port+'</span>'):'';
  var mL=srv.memUsed!==null&&srv.memTot!==null&&srv.memUsed!==undefined&&srv.memTot!==undefined?srv.memUsed+'/'+srv.memTot+'G':null;
  var dL=srv.diskUsed!==null&&srv.diskTot!==null&&srv.diskUsed!==undefined&&srv.diskTot!==undefined?srv.diskUsed+'/'+srv.diskTot+'G':null;
  var errH=srv.error?'<span class="srv-spacer" style="min-width:0;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.65rem;color:var(--c-er)" title="'+esc(srv.error)+'"><i class="bi bi-exclamation-circle"></i> '+esc(srv.error)+'</span>':'<span class="srv-spacer"></span>';

  // Tooltip
  var tipR='<tr><td>Server</td><td>'+esc(srv.name)+'</td></tr>'
    +'<tr><td>Hostname</td><td>'+esc(srv.hostname||'—')+'</td></tr>'
    +'<tr><td>IP</td><td>'+esc(srv.ip||'—')+'</td></tr>'
    +'<tr><td>Ping</td><td>'+(srv.ping!==null&&srv.ping!==undefined?srv.ping+'ms':'—')+'</td></tr>'
    +'<tr><td>TTL</td><td>'+(srv.ttl!==null&&srv.ttl!==undefined?srv.ttl:'—')+'</td></tr>'
    +'<tr><td>Port</td><td>'+(srv.port!==null&&srv.port!==undefined?(srv.portOpen?'Open':'Closed')+' (:'+srv.port+')':'—')+'</td></tr>'
    +'<tr><td>Type</td><td>'+esc(srv.type)+'</td></tr>'
    +'<tr><td>CSV Status</td><td>'+esc(srv.csvStatus||'—')+'</td></tr>'
    +'<tr><td>Scanned</td><td>'+esc(srv.ts)+'</td></tr>';
  if(HAS_WMI) tipR+='<tr><td class="tip-sec" colspan="2">System Metrics</td></tr>'
    +'<tr><td>OS</td><td>'+esc(srv.os||'—')+'</td></tr>'
    +'<tr><td>CPU</td><td>'+(srv.cpu!==null&&srv.cpu!==undefined?srv.cpu+'%':'—')+'</td></tr>'
    +'<tr><td>Memory</td><td>'+(mL?mL+' ('+srv.memPct+'%)':'—')+'</td></tr>'
    +'<tr><td>Disk C:</td><td>'+(dL?dL+' ('+srv.diskPct+'%)':'—')+'</td></tr>'
    +'<tr><td>Last Reboot</td><td>'+rebootFull(srv.reboot)+'</td></tr>';
  if(srv.error) tipR+='<tr><td>Error</td><td class="tip-err">'+esc(srv.error)+'</td></tr>';

  row.innerHTML='<span class="s-dot '+dotCls(srv.health)+'"></span>'
    +'<span class="srv-name" title="'+esc(srv.name)+'">'+esc(srv.name)+'</span>'
    +'<span class="col-ip">'+esc(srv.ip||'—')+'</span>'
    +'<span class="col-ping '+pingCls(srv.ping)+'" data-ms="'+(srv.ping!==null&&srv.ping!==undefined?srv.ping:'')+'">'+ptx+'</span>'
    +'<span class="col-port">'+phH+'</span>'
    +'<span class="col-cpu" data-pct="'+(srv.cpu!==null&&srv.cpu!==undefined?srv.cpu:'')+'">'+metCell(srv.cpu,S.cpuWarn,S.cpuCrit)+'</span>'
    +'<span class="col-mem" data-pct="'+(srv.memPct!==null&&srv.memPct!==undefined?srv.memPct:'')+'">'+metCell(srv.memPct,S.memWarn,S.memCrit,mL)+'</span>'
    +'<span class="col-disk" data-pct="'+(srv.diskPct!==null&&srv.diskPct!==undefined?srv.diskPct:'')+'">'+metCell(srv.diskPct,S.diskWarn,S.diskCrit,dL)+'</span>'
    +'<span class="col-reboot" title="'+rebootFull(srv.reboot)+'">'+rebootAge(srv.reboot)+'</span>'
    +errH
    +'<span class="col-badge h-badge '+badgeCls(srv.health)+'">'+esc(srv.health)+'</span>'
    +'<button class="detail-btn" id="db-'+sid+'" onclick="togDetail(\''+sid+'\')" title="Show details"><i class="bi bi-chevron-down"></i></button>'
    +'<div class="tip"><table>'+tipR+'</table></div>';
  return row;
}

/* ── Detail toggles ── */
window.togDetail=function(sid){
  var p=document.getElementById('dp-'+sid); if(!p) return;
  var b=document.getElementById('db-'+sid);
  var show=p.style.display==='none';
  p.style.display=show?'':'none';
  if(b) b.classList.toggle('active',show);
};
window.showDTab=function(sid,tab){
  ['svcs','evts','patches','apps'].forEach(function(t){
    var pn=document.getElementById('dtc-'+sid+'-'+t); if(pn) pn.style.display=t===tab?'':'none';
    var bt=document.getElementById('dtt-'+sid+'-'+t); if(bt) bt.classList.toggle('active',t===tab);
  });
};

/* ── Tree toggles ── */
window.togApp=function(ai){ var b=document.getElementById('ab-'+ai),h=document.getElementById('ah-'+ai),c=document.getElementById('ac-'+ai); if(!b) return; var o=b.classList.toggle('show'); c.classList.toggle('open',o); h.classList.toggle('open',o); };
window.togEnv=function(ai,ei){ var b=document.getElementById('eb-'+ai+'-'+ei),c=document.getElementById('ec-'+ai+'-'+ei); if(!b) return; b.classList.toggle('show'); c.classList.toggle('open'); };
window.expandAll=function(){
  document.querySelectorAll('.app-body').forEach(function(e){e.classList.add('show')});
  document.querySelectorAll('.env-body').forEach(function(e){e.classList.add('show')});
  document.querySelectorAll('.app-chv,.env-chv').forEach(function(e){e.classList.add('open')});
  document.querySelectorAll('.app-hdr').forEach(function(e){e.classList.add('open')});
};
window.collapseAll=function(){
  document.querySelectorAll('.app-body').forEach(function(e){e.classList.remove('show')});
  document.querySelectorAll('.env-body').forEach(function(e){e.classList.remove('show')});
  document.querySelectorAll('.app-chv,.env-chv').forEach(function(e){e.classList.remove('open')});
  document.querySelectorAll('.app-hdr').forEach(function(e){e.classList.remove('open')});
};

/* ── Filtering ── */
var activeFilter='all';
window.setFilter=function(el,f){ activeFilter=f; document.querySelectorAll('.fp').forEach(function(p){p.classList.remove('active')}); el.classList.add('active'); applyFilters(); };
window.applyFilters=function(){
  var q=(document.getElementById('searchBox').value||'').trim().toLowerCase(); var count=0;
  document.querySelectorAll('.srv-row').forEach(function(row){
    var mf=activeFilter==='all'||row.getAttribute('data-health')===activeFilter;
    var ms=!q||row.getAttribute('data-name').indexOf(q)>=0||row.getAttribute('data-ip').indexOf(q)>=0;
    var ma=S.showArchived||row.getAttribute('data-csvstatus')!=='Archived';
    var show=mf&&ms&&ma; row.classList.toggle('hidden',!show);
    // Also hide detail panel of hidden rows
    var dp=row.nextElementSibling; if(dp&&dp.id&&dp.id.indexOf('dp-')===0&&!show) dp.style.display='none';
    if(show) count++;
  });
  document.getElementById('visCount').textContent=count;
  if(q||activeFilter!=='all'){
    document.querySelectorAll('.app-card').forEach(function(card){
      if(card.querySelector('.srv-row:not(.hidden)')){
        card.querySelector('.app-body').classList.add('show');
        card.querySelector('.app-hdr').classList.add('open');
        card.querySelectorAll('.app-chv').forEach(function(c){c.classList.add('open')});
        card.querySelectorAll('.env-body').forEach(function(e){e.classList.add('show')});
        card.querySelectorAll('.env-chv').forEach(function(c){c.classList.add('open')});
      }
    });
  }
  document.getElementById('noResults').style.display=count===0?'':'none';
};

/* ── Live threshold recolour ── */
function recolorMetrics(){
  document.querySelectorAll('.col-ping[data-ms]').forEach(function(el){ var v=el.getAttribute('data-ms'); if(v==='') return; el.className='col-ping '+pingCls(+v); });
  function recolorMc(sel,w,c){ document.querySelectorAll(sel).forEach(function(el){ var v=el.getAttribute('data-pct'); if(v==='') return; var m=el.querySelector('.mc'); if(m) m.className='mc '+metCls(+v,w,c); }); }
  recolorMc('.col-cpu',S.cpuWarn,S.cpuCrit); recolorMc('.col-mem',S.memWarn,S.memCrit); recolorMc('.col-disk',S.diskWarn,S.diskCrit);
}

/* ── CSV Export ── */
window.exportCsv=function(){
  var cols=['ServerName','App','Env','Type','Health','IP','Hostname','PingMs','TTL','Port','PortOpen',
    'CPU%','MemTotGB','MemUsedGB','Mem%','DiskTotGB','DiskUsedGB','Disk%','LastRebootUTC','OS',
    'SVCsDown','EventCount','PatchCount','AppCount','CSVStatus','Error','Timestamp'];
  var rows=[cols.join(',')];
  DATA.forEach(function(app){ app.environments.forEach(function(env){ env.servers.forEach(function(s){
    var svcsD=s.svcs?s.svcs.filter(function(x){return x.st==='Stopped';}).length:0;
    var cells=[s.name,s.app,s.env,s.type,s.health,s.ip,s.hostname,
      s.ping!==null&&s.ping!==undefined?s.ping:'',s.ttl!==null&&s.ttl!==undefined?s.ttl:'',
      s.port!==null&&s.port!==undefined?s.port:'',s.portOpen!==null&&s.portOpen!==undefined?s.portOpen:'',
      s.cpu!==null&&s.cpu!==undefined?s.cpu:'',s.memTot!==null&&s.memTot!==undefined?s.memTot:'',
      s.memUsed!==null&&s.memUsed!==undefined?s.memUsed:'',s.memPct!==null&&s.memPct!==undefined?s.memPct:'',
      s.diskTot!==null&&s.diskTot!==undefined?s.diskTot:'',s.diskUsed!==null&&s.diskUsed!==undefined?s.diskUsed:'',
      s.diskPct!==null&&s.diskPct!==undefined?s.diskPct:'',s.reboot||'',s.os||'',
      svcsD,(s.evts?s.evts.length:0),(s.patches?s.patches.length:0),(s.apps?s.apps.length:0),
      s.csvStatus||'',s.error||'',s.ts];
    rows.push(cells.map(function(v){ v=(v===null||v===undefined)?'':String(v);
      return(v.indexOf(',')>=0||v.indexOf('"')>=0||v.indexOf('\n')>=0)?'"'+v.replace(/"/g,'""')+'"':v; }).join(','));
  }); }); });
  var blob=new Blob([rows.join('\r\n')],{type:'text/csv;charset=utf-8;'});
  var a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download='ServerHealth_'+new Date().toISOString().slice(0,10).replace(/-/g,'')+'.csv';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
};

/* ── Charts ── */
var CI={};
function mkChart(id,cfg){ if(CI[id]) CI[id].destroy(); var el=document.getElementById(id); if(el) CI[id]=new Chart(el,cfg); }
function initCharts(){
  Chart.defaults.color='#8898aa'; Chart.defaults.borderColor='#263348';
  var g='rgba(38,51,72,.7)',ys={beginAtZero:true,grid:{color:g}};
  var eL=[%%ENV_LABELS%%],eD=[%%ENV_COUNTS%%];
  mkChart('chartEnv',{type:'doughnut',data:{labels:eL,datasets:[{data:eD,backgroundColor:eL.map(function(l){return ENV_HEX[l]||'#64748b';}),borderColor:'#0b1220',borderWidth:3,hoverOffset:6}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{boxWidth:10,padding:9,color:'#8898aa'}},tooltip:{callbacks:{label:function(c){return ' '+c.label+': '+c.raw+' server'+(c.raw!==1?'s':'');}}}}}});
  var tL=[%%TYPE_LABELS%%],tD=[%%TYPE_AVGS%%];
  mkChart('chartType',{type:'bar',data:{labels:tL,datasets:[{label:'ms',data:tD,backgroundColor:tL.map(function(_,i){return PAL[i%PAL.length];}),borderRadius:5,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:g}},y:Object.assign({ticks:{callback:function(v){return v+'ms';}}},ys)}}});
  mkChart('chartHealth',{type:'bar',data:{labels:['Healthy','Warning','Degraded','Critical/Offline'],datasets:[{data:[%%HEALTH_DATA%%],backgroundColor:['#34d399','#fbbf24','#fb923c','#f87171'],borderRadius:5,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:g}},y:Object.assign({ticks:{stepSize:1}},ys)}}});
  if(HAS_WMI){
    document.getElementById('chartRow2').style.display='';
    var cL=[%%CPU_APP_LABELS%%],cD=[%%CPU_APP_DATA%%];
    mkChart('chartCpu',{type:'bar',data:{labels:cL,datasets:[{label:'CPU%',data:cD,backgroundColor:cL.map(function(_,i){return PAL[i%PAL.length];}),borderRadius:5,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:g}},y:Object.assign({max:100,ticks:{callback:function(v){return v+'%';}}},ys)}}});
    var mL=[%%MEM_TYPE_LABELS%%],mD=[%%MEM_TYPE_DATA%%];
    mkChart('chartMem',{type:'bar',data:{labels:mL,datasets:[{label:'Mem%',data:mD,backgroundColor:['#22d3ee','#a78bfa','#fb923c','#34d399'],borderRadius:5,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{color:g}},y:Object.assign({max:100,ticks:{callback:function(v){return v+'%';}}},ys)}}});
  }
}

/* ── Init ── */
document.addEventListener('DOMContentLoaded',function(){
  loadSettings(); buildTree(); applyAllSettings(); initCharts(); syncCfgUI();
});
}());
</script>
</body>
</html>
'@

    # ── Inject values ─────────────────────────────────────────────────────
    $warnDeg=$warning+$degraded
    $html=$html.Replace('%%GEN_TIME%%',     $genTime)
    $html=$html.Replace('%%PS_VER%%',       $psVer)
    $html=$html.Replace('%%TOTAL%%',        [string]$total)
    $html=$html.Replace('%%HEALTHY%%',      [string]$healthy)
    $html=$html.Replace('%%WARN_DEG%%',     [string]$warnDeg)
    $html=$html.Replace('%%CRITICAL%%',     [string]$critical)
    $html=$html.Replace('%%AVG_PING%%',     [string]$avgPing)
    $html=$html.Replace('%%AVG_CPU%%',      $avgCpuJs)
    $html=$html.Replace('%%AVG_MEM%%',      $avgMemJs)
    $html=$html.Replace('%%URLS_OK%%',      [string]$urlsOk)
    $html=$html.Replace('%%URLS_DOWN%%',    [string]$urlsDown)
    $html=$html.Replace('%%JSON_DATA%%',    $jsonData)
    $html=$html.Replace('%%URL_DATA%%',     $urlDataJs)
    $html=$html.Replace('%%HAS_WMI%%',      $hasWmiJs)
    $html=$html.Replace('%%HAS_URLS%%',     $hasUrlJs)
    $html=$html.Replace('%%HAS_SVCS%%',     $hasSvcsJs)
    $html=$html.Replace('%%ENV_LABELS%%',   $envL)
    $html=$html.Replace('%%ENV_COUNTS%%',   $envC)
    $html=$html.Replace('%%TYPE_LABELS%%',  $typeL)
    $html=$html.Replace('%%TYPE_AVGS%%',    $typeAvg)
    $html=$html.Replace('%%HEALTH_DATA%%',  $healthD)
    $html=$html.Replace('%%CPU_APP_LABELS%%',$cpuAL)
    $html=$html.Replace('%%CPU_APP_DATA%%', $cpuAD)
    $html=$html.Replace('%%MEM_TYPE_LABELS%%',$memTL)
    $html=$html.Replace('%%MEM_TYPE_DATA%%', $memTD)

    # ── Write ─────────────────────────────────────────────────────────────
    $abs=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $pd=Split-Path $abs -Parent
    if($pd -and -not(Test-Path -LiteralPath $pd)){ New-Item -ItemType Directory -Path $pd -Force|Out-Null }
    try {
        [System.IO.File]::WriteAllText($abs,$html,[System.Text.Encoding]::UTF8)
        $kb=[math]::Round(([System.IO.FileInfo]$abs).Length/1KB,1)
        Write-Host "[OK] Dashboard saved: $abs  ($kb KB)" -ForegroundColor Green
    } catch { Write-Error "Failed to write HTML: $($_.Exception.Message)" }
}
#endregion

#region ── Main ───────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '╔═══════════════════════════════════════════════════╗' -ForegroundColor Cyan
Write-Host '║  Server Health Report Generator  v4.0             ║' -ForegroundColor Cyan
Write-Host '╚═══════════════════════════════════════════════════╝' -ForegroundColor Cyan
Write-Host "  PowerShell    : $($PSVersionTable.PSVersion)"        -ForegroundColor Gray
Write-Host "  CSV           : $CsvPath"                             -ForegroundColor Gray
Write-Host "  Services INI  : $ServicesIniPath ($(if(Test-Path $ServicesIniPath){'found'}else{'not found'}))" -ForegroundColor Gray
Write-Host "  URLs INI      : $UrlsIniPath ($(if(Test-Path $UrlsIniPath){'found'}else{'not found'}))"         -ForegroundColor Gray
Write-Host "  Output        : $OutputPath"                          -ForegroundColor Gray
Write-Host "  Sys Metrics   : $(if($SkipSystemMetrics){'DISABLED'}else{'ENABLED (WMI + PSRemoting, '+$WmiTimeoutSec+'s)'})" -ForegroundColor Gray
Write-Host "  URL Check     : $(if($SkipUrlCheck){'DISABLED'}else{'ENABLED ('+$UrlTimeoutSec+'s timeout)'})" -ForegroundColor Gray
Write-Host ''

if (-not(Test-Path -LiteralPath $CsvPath)){ Write-Error "CSV not found: '$CsvPath'"; exit 1 }
$csvData=Import-Csv -Path $CsvPath
$req=@('ServerName','ApplicationName','Environment','ServerType','Status')
$cols=($csvData|Get-Member -MemberType NoteProperty).Name
$miss=$req|Where-Object{$_ -notin $cols}
if($miss){ Write-Error "CSV missing: $($miss -join ', ')"; exit 1 }
Write-Host "[*] Loaded $($csvData.Count) row(s) from '$CsvPath'." -ForegroundColor Cyan

$sw=[System.Diagnostics.Stopwatch]::StartNew()
$srvResults=Invoke-ServerScan -Servers $csvData -PingTimeoutMs $PingTimeoutMs `
    -MaxConcurrency $MaxConcurrency -EnableWmi(-not $SkipSystemMetrics.IsPresent) `
    -WmiTimeoutSec $WmiTimeoutSec -ServiceMap $Script:ServiceMap
$sw.Stop()
Write-Host ("[*] Scan done in {0:n1}s – {1} result(s)" -f $sw.Elapsed.TotalSeconds,$srvResults.Count) -ForegroundColor Cyan

$urlResults=@()
if (-not $SkipUrlCheck.IsPresent){
    $urlResults=Invoke-UrlCheck -UrlMap $Script:UrlMap -ScanResults $srvResults `
        -TimeoutSec $UrlTimeoutSec -WmiTimeoutSec $WmiTimeoutSec -CheckPool(-not $SkipSystemMetrics.IsPresent)
}

if(-not $srvResults){ $srvResults=@() }
ConvertTo-HtmlDashboard -ScanResults $srvResults -UrlResults $urlResults -OutputPath $OutputPath

try {
    $abs=(Get-Item -LiteralPath $OutputPath).FullName
    Write-Host "`n[*] Open in browser:" -ForegroundColor Green
    Write-Host "    file:///$($abs -replace '\\','/')" -ForegroundColor White
} catch { Write-Host "`n[*] Report: $OutputPath" -ForegroundColor Green }
#endregion
