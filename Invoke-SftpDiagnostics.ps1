<#
.SYNOPSIS
    Staged, multi-area diagnostic tool for SFTP "Server refused the key" failures
    (WinSCP.com automation vs working WinSCP GUI). Produces a detailed HTML report.

.DESCRIPTION
    Runs the following stages, each independent and fault-tolerant (a failure in
    one stage does not stop later stages):

      Stage 1 - Execution context   (who/how this runs)
      Stage 2 - WinSCP installation audit (GUI vs .com version skew)
      Stage 3 - Private key file analysis (existence, format, ACL/permissions)
      Stage 4 - Public key analysis (type, bit length, fingerprints)
      Stage 5 - Network reachability + raw SSH banner grab (no auth attempted)
      Stage 6 - Live authenticated connection test via winscp.com, full debug log,
                with automatic parsing of algorithm negotiation / refusal lines
      Stage 7 - Root-cause correlation and confidence scoring
      Stage 8 - HTML report generation

    All findings are collected into a single result set and rendered to a
    self-contained HTML file (no external assets) at the end.

.PARAMETER SftpHost
    SFTP server hostname or IP.

.PARAMETER SftpPort
    SFTP server port (default 22).

.PARAMETER Username
    SFTP username.

.PARAMETER Password
    SFTP password. Leave blank for key-only auth. NOTE: passed on the command
    line / stored in memory only for this run; not written to disk except
    inside the WinSCP debug log if -EnablePasswordLogging is used.

.PARAMETER PrivateKeyPath
    Path to the private key (.ppk or OpenSSH format) used by your automation.

.PARAMETER PublicKeyPath
    Optional path to the matching .pub file, for key-type/fingerprint analysis.
    If omitted, Stage 4 is skipped.

.PARAMETER KnownHostFingerprint
    Expected SSH host key fingerprint, as shown in WinSCP GUI's
    Session > Server/Protocol Information, or from the server admin.
    If omitted, Stage 6's live test will not strictly verify the host key
    (diagnostics only - do not use this mode for production).

.PARAMETER WinScpComPath
    Full path to the winscp.com your automation actually invokes.

.PARAMETER EnablePasswordLogging
    If set, uses WinSCP /loglevel=2* (includes password in the debug log).
    Only use in a secured, temporary location; the script warns and can
    delete the log for you at the end.

.PARAMETER OutputDir
    Where logs and the HTML report are written. Defaults to a timestamped
    folder under %TEMP%.

.EXAMPLE
    .\Invoke-SftpDiagnostics.ps1 -SftpHost sftp.example.com -Username svc_transfer `
        -PrivateKeyPath "C:\keys\transfer.ppk" -PublicKeyPath "C:\keys\transfer.pub" `
        -WinScpComPath "C:\Automation\winscp.com" `
        -KnownHostFingerprint "ssh-ed25519 255 xx:xx:...:xx"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SftpHost,
    [int]$SftpPort = 22,
    [Parameter(Mandatory = $true)][string]$Username,
    [string]$Password = "",
    [Parameter(Mandatory = $true)][string]$PrivateKeyPath,
    [string]$PublicKeyPath = "",
    [string]$KnownHostFingerprint = "",
    [Parameter(Mandatory = $true)][string]$WinScpComPath,
    [switch]$EnablePasswordLogging,
    [string]$OutputDir = "$env:TEMP\SftpDiag_$(Get-Date -Format yyyyMMdd_HHmmss)"
)

# ======================================================================
# Shared result collection
# ======================================================================
$Script:Results = New-Object System.Collections.Generic.List[Object]
$Script:Signals  = New-Object System.Collections.Generic.List[Object]  # for root-cause scoring

function Add-Result {
    param(
        [string]$Stage,
        [string]$Check,
        [ValidateSet("Pass","Warn","Fail","Info")][string]$Status,
        [string]$Details,
        [string]$Recommendation = ""
    )
    $Script:Results.Add([PSCustomObject]@{
        Stage          = $Stage
        Check          = $Check
        Status         = $Status
        Details        = $Details
        Recommendation = $Recommendation
        Timestamp      = (Get-Date -Format "HH:mm:ss")
    })
    $color = switch ($Status) { "Pass" {"Green"} "Warn" {"Yellow"} "Fail" {"Red"} default {"Gray"} }
    Write-Host "[$Stage] $Check : $Status - $Details" -ForegroundColor $color
}

function Add-Signal {
    # Evidence used later for root-cause scoring
    param([string]$Cause, [int]$Weight, [string]$Evidence)
    $Script:Signals.Add([PSCustomObject]@{ Cause = $Cause; Weight = $Weight; Evidence = $Evidence })
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
Write-Host "Output directory: $OutputDir" -ForegroundColor Cyan
Write-Host ""

# ======================================================================
# STAGE 1 - Execution context
# ======================================================================
Write-Host "===== STAGE 1: Execution Context =====" -ForegroundColor Cyan
try {
    $whoAmI = whoami
    $isInteractive = [Environment]::UserInteractive
    Add-Result -Stage "1-Context" -Check "Running as" -Status "Info" -Details "$whoAmI (interactive: $isInteractive)"

    $psVersion = $PSVersionTable.PSVersion.ToString()
    Add-Result -Stage "1-Context" -Check "PowerShell version" -Status "Info" -Details $psVersion

    $osInfo = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue)
    if ($osInfo) {
        Add-Result -Stage "1-Context" -Check "OS" -Status "Info" -Details "$($osInfo.Caption) (Build $($osInfo.BuildNumber))"
    }

    if ($whoAmI -match '\\(svc|service|system)') {
        Add-Result -Stage "1-Context" -Check "Service account pattern" -Status "Warn" `
            -Details "Account name suggests a service/scheduled-task identity." `
            -Recommendation "Confirm this account's profile has access to the same key file path and any cached host key entries as your interactive/GUI session."
    }
} catch {
    Add-Result -Stage "1-Context" -Check "Context collection" -Status "Fail" -Details $_.Exception.Message
}

# ======================================================================
# STAGE 2 - WinSCP installation audit
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 2: WinSCP Installation Audit =====" -ForegroundColor Cyan
$guiExePath = $null
try {
    $guiCandidates = @(
        "$env:ProgramFiles\WinSCP\WinSCP.exe",
        "${env:ProgramFiles(x86)}\WinSCP\WinSCP.exe"
    )
    $guiExePath = $guiCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($guiExePath) {
        $guiVersion = (Get-Item $guiExePath).VersionInfo.FileVersion
        Add-Result -Stage "2-WinSCP" -Check "GUI installation found" -Status "Pass" -Details "$guiExePath (version $guiVersion)"
    } else {
        Add-Result -Stage "2-WinSCP" -Check "GUI installation found" -Status "Warn" -Details "No standard WinSCP GUI install path found; cannot compare versions."
    }

    if (Test-Path $WinScpComPath) {
        $comVersion = (Get-Item $WinScpComPath).VersionInfo.FileVersion
        $comModified = (Get-Item $WinScpComPath).LastWriteTime
        Add-Result -Stage "2-WinSCP" -Check "Automation winscp.com found" -Status "Pass" `
            -Details "$WinScpComPath (version $comVersion, modified $comModified)"

        if ($guiExePath) {
            if ($comVersion -ne $guiVersion) {
                Add-Result -Stage "2-WinSCP" -Check "Version comparison" -Status "Fail" `
                    -Details "Automation winscp.com ($comVersion) differs from installed GUI ($guiVersion)." `
                    -Recommendation "Update the winscp.com your automation calls to match the current GUI version, or repoint your script at the GUI's install folder. Older builds may not support current SSH signature algorithms (e.g. rsa-sha2-256/512), causing key refusals after server-side hardening."
                Add-Signal -Cause "WinSCP version skew (old client, legacy algorithm offered)" -Weight 40 -Evidence "Script's winscp.com v$comVersion vs GUI v$guiVersion"
            } else {
                Add-Result -Stage "2-WinSCP" -Check "Version comparison" -Status "Pass" -Details "Versions match ($comVersion)."
            }
        }
    } else {
        Add-Result -Stage "2-WinSCP" -Check "Automation winscp.com found" -Status "Fail" `
            -Details "Not found at: $WinScpComPath" `
            -Recommendation "Verify the exact path your automation code invokes."
        Add-Signal -Cause "winscp.com path invalid/missing" -Weight 50 -Evidence "Configured path not found: $WinScpComPath"
    }
} catch {
    Add-Result -Stage "2-WinSCP" -Check "Installation audit" -Status "Fail" -Details $_.Exception.Message
}

# ======================================================================
# STAGE 3 - Private key file analysis
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 3: Private Key Analysis =====" -ForegroundColor Cyan
try {
    if (Test-Path $PrivateKeyPath) {
        Add-Result -Stage "3-PrivateKey" -Check "File exists" -Status "Pass" -Details $PrivateKeyPath

        $firstLines = Get-Content $PrivateKeyPath -TotalCount 3
        if ($firstLines -match "PuTTY-User-Key-File-3") {
            Add-Result -Stage "3-PrivateKey" -Check "Format" -Status "Warn" -Details "PuTTY PPK v3 format." `
                -Recommendation "PPK v3 requires a reasonably current WinSCP/PuTTY build. If Stage 2 found an old winscp.com, it may not read this key at all (distinct from an algorithm-refusal error, but worth ruling out)."
        } elseif ($firstLines -match "PuTTY-User-Key-File-2") {
            Add-Result -Stage "3-PrivateKey" -Check "Format" -Status "Pass" -Details "PuTTY PPK v2 format (widely supported)."
        } elseif ($firstLines -match "BEGIN OPENSSH PRIVATE KEY") {
            Add-Result -Stage "3-PrivateKey" -Check "Format" -Status "Pass" -Details "OpenSSH private key format."
        } elseif ($firstLines -match "BEGIN RSA PRIVATE KEY") {
            Add-Result -Stage "3-PrivateKey" -Check "Format" -Status "Pass" -Details "PEM/RSA private key format."
        } else {
            Add-Result -Stage "3-PrivateKey" -Check "Format" -Status "Warn" -Details "Unrecognized header; verify this is really a private key."
        }

        try {
            $acl = Get-Acl $PrivateKeyPath
            $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            $accessEntries = $acl.Access | Where-Object {
                $_.IdentityReference -eq $currentUser -or $_.IdentityReference -match "Everyone|Authenticated Users|Users"
            }
            if ($accessEntries) {
                $summary = ($accessEntries | ForEach-Object { "$($_.IdentityReference): $($_.FileSystemRights)" }) -join "; "
                Add-Result -Stage "3-PrivateKey" -Check "ACL / access for current user" -Status "Info" -Details $summary
            } else {
                Add-Result -Stage "3-PrivateKey" -Check "ACL / access for current user" -Status "Warn" `
                    -Details "Current identity ($currentUser) not explicitly listed in ACL; access may rely on inherited/group permissions only." `
                    -Recommendation "If the automation runs as a different (service) account, explicitly verify THAT account has Read access to this exact file."
            }
        } catch {
            Add-Result -Stage "3-PrivateKey" -Check "ACL check" -Status "Warn" -Details "Could not read ACL: $($_.Exception.Message)"
        }
    } else {
        Add-Result -Stage "3-PrivateKey" -Check "File exists" -Status "Fail" -Details "Not found: $PrivateKeyPath" `
            -Recommendation "Confirm the path is correct and accessible from the account that runs the automation."
        Add-Signal -Cause "Private key inaccessible/missing in this context" -Weight 45 -Evidence "Path not found: $PrivateKeyPath"
    }
} catch {
    Add-Result -Stage "3-PrivateKey" -Check "Private key analysis" -Status "Fail" -Details $_.Exception.Message
}

# ======================================================================
# STAGE 4 - Public key analysis (type / bit length / fingerprints)
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 4: Public Key Analysis =====" -ForegroundColor Cyan
$Script:DetectedKeyType = $null

function Read-SshField {
    param([byte[]]$Bytes, [ref]$Offset)
    $o = $Offset.Value
    $len = ([int]$Bytes[$o] -shl 24) -bor ([int]$Bytes[$o+1] -shl 16) -bor ([int]$Bytes[$o+2] -shl 8) -bor [int]$Bytes[$o+3]
    $o += 4
    $field = $Bytes[$o..($o + $len - 1)]
    $o += $len
    $Offset.Value = $o
    return $field
}

if ([string]::IsNullOrWhiteSpace($PublicKeyPath)) {
    Add-Result -Stage "4-PublicKey" -Check "Public key analysis" -Status "Info" -Details "Skipped (no -PublicKeyPath supplied)."
} elseif (-not (Test-Path $PublicKeyPath)) {
    Add-Result -Stage "4-PublicKey" -Check "File exists" -Status "Warn" -Details "Not found: $PublicKeyPath"
} else {
    try {
        $line = (Get-Content $PublicKeyPath -TotalCount 1).Trim()
        $parts = $line -split '\s+', 3
        if ($parts.Count -lt 2) {
            Add-Result -Stage "4-PublicKey" -Check "Parse .pub" -Status "Warn" -Details "Unexpected format in first line."
        } else {
            $keyType = $parts[0]
            $blob = [Convert]::FromBase64String($parts[1])
            $offset = 0
            Read-SshField -Bytes $blob -Offset ([ref]$offset) | Out-Null   # type field (already known from $keyType)

            $bitLength = "unknown"
            if ($keyType -eq "ssh-rsa") {
                Read-SshField -Bytes $blob -Offset ([ref]$offset) | Out-Null  # exponent
                $n = Read-SshField -Bytes $blob -Offset ([ref]$offset)       # modulus
                if ($n.Length -gt 0 -and $n[0] -eq 0) { $n = $n[1..($n.Length - 1)] }
                $bits = $n.Length * 8
                $top = $n[0]
                for ($b = 7; $b -ge 0; $b--) { if (($top -band (1 -shl $b)) -eq 0) { $bits-- } else { break } }
                $bitLength = $bits
            } elseif ($keyType -eq "ssh-ed25519") {
                $bitLength = 256
            } elseif ($keyType -like "ecdsa-sha2-*") {
                $curve = [System.Text.Encoding]::ASCII.GetString((Read-SshField -Bytes $blob -Offset ([ref]$offset)))
                $bitLength = switch ($curve) { "nistp256" {256} "nistp384" {384} "nistp521" {521} default {"unknown"} }
            }

            $sha256 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($blob)
            $sha256Fp = "SHA256:" + [Convert]::ToBase64String($sha256).TrimEnd('=')

            $Script:DetectedKeyType = $keyType
            Add-Result -Stage "4-PublicKey" -Check "Key type / size" -Status "Info" -Details "$keyType, $bitLength bits"
            Add-Result -Stage "4-PublicKey" -Check "Fingerprint (SHA256)" -Status "Info" -Details $sha256Fp `
                -Recommendation "Ask the server admin to confirm this exact fingerprint appears in the account's authorized_keys (ssh-keygen -lf ~/.ssh/authorized_keys)."

            if ($keyType -eq "ssh-rsa") {
                Add-Result -Stage "4-PublicKey" -Check "Algorithm exposure" -Status "Warn" `
                    -Details "Key type is 'ssh-rsa', which implies the legacy ssh-rsa/SHA-1 signature algorithm may be used during auth (same key, different signature method is possible with modern clients: rsa-sha2-256/512)." `
                    -Recommendation "If the server disabled ssh-rsa/SHA-1 signatures recently (common OpenSSH 8.8+ default), an older SSH client will be refused even though the key itself is valid and authorized."
                Add-Signal -Cause "RSA key using legacy signature algorithm rejected by hardened server" -Weight 35 -Evidence "Public key type is ssh-rsa ($bitLength bits)"
            }
        }
    } catch {
        Add-Result -Stage "4-PublicKey" -Check "Parse .pub" -Status "Fail" -Details $_.Exception.Message
    }
}

# ======================================================================
# STAGE 5 - Network reachability + raw SSH banner grab (no auth)
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 5: Network & SSH Banner =====" -ForegroundColor Cyan
try {
    $tcpTest = Test-NetConnection -ComputerName $SftpHost -Port $SftpPort -WarningAction SilentlyContinue
    if ($tcpTest.TcpTestSucceeded) {
        Add-Result -Stage "5-Network" -Check "TCP reachability" -Status "Pass" -Details "$SftpHost`:$SftpPort is reachable."
    } else {
        Add-Result -Stage "5-Network" -Check "TCP reachability" -Status "Fail" -Details "Could not reach $SftpHost`:$SftpPort." `
            -Recommendation "Check firewall/network path before investigating SSH-level causes further."
        Add-Signal -Cause "Network/firewall blocking connection" -Weight 60 -Evidence "TCP connect to $SftpHost`:$SftpPort failed"
    }
} catch {
    Add-Result -Stage "5-Network" -Check "TCP reachability" -Status "Warn" -Details "Test-NetConnection failed to run: $($_.Exception.Message)"
}

try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($SftpHost, $SftpPort, $null, $null)
    $ok = $iar.AsyncWaitHandle.WaitOne(5000, $false)
    if ($ok -and $client.Connected) {
        $client.EndConnect($iar)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $buffer = New-Object byte[] 256
        $read = $stream.Read($buffer, 0, 256)
        $banner = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read).Trim()
        $client.Close()

        Add-Result -Stage "5-Network" -Check "SSH server banner" -Status "Info" -Details $banner

        if ($banner -match "OpenSSH_(\d+)\.(\d+)") {
            $major = [int]$Matches[1]; $minor = [int]$Matches[2]
            if ($major -gt 8 -or ($major -eq 8 -and $minor -ge 8)) {
                Add-Result -Stage "5-Network" -Check "Server OpenSSH version policy" -Status "Warn" `
                    -Details "Server reports OpenSSH $major.$minor. OpenSSH 8.8+ disables the legacy ssh-rsa/SHA-1 signature algorithm by default." `
                    -Recommendation "If your key/client is limited to ssh-rsa, this version is consistent with sudden key refusals after a server-side OpenSSH upgrade or patch."
                Add-Signal -Cause "Server OpenSSH version disables legacy ssh-rsa signatures by default" -Weight 30 -Evidence "Banner: $banner"
            } else {
                Add-Result -Stage "5-Network" -Check "Server OpenSSH version policy" -Status "Pass" -Details "OpenSSH $major.$minor predates the default ssh-rsa deprecation."
            }
        }
    } else {
        Add-Result -Stage "5-Network" -Check "SSH server banner" -Status "Warn" -Details "Could not connect to grab banner within timeout."
    }
} catch {
    Add-Result -Stage "5-Network" -Check "SSH server banner" -Status "Warn" -Details "Banner grab failed: $($_.Exception.Message)"
}

# ======================================================================
# STAGE 6 - Live authenticated connection test via winscp.com
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 6: Live Connection Test =====" -ForegroundColor Cyan
$sessionLog = Join-Path $OutputDir "winscp_session.log"
$scriptFile = Join-Path $OutputDir "diag_script.txt"
$logLevel = if ($EnablePasswordLogging) { "2*" } else { "2" }

if (-not (Test-Path $WinScpComPath)) {
    Add-Result -Stage "6-LiveTest" -Check "Live connection test" -Status "Fail" -Details "Skipped - winscp.com not found at $WinScpComPath"
} else {
    try {
        $hostKeySwitch = if ($KnownHostFingerprint) { " -hostkey=`"$KnownHostFingerprint`"" } else { "" }
        $openLine = "open sftp://$Username`:$Password@$SftpHost`:$SftpPort/$hostKeySwitch -privatekey=`"$PrivateKeyPath`""

        @"
option batch on
option confirm off
$openLine
pwd
exit
"@ | Set-Content -Path $scriptFile -Encoding ASCII

        if (-not $KnownHostFingerprint) {
            Add-Result -Stage "6-LiveTest" -Check "Host key verification" -Status "Warn" `
                -Details "No -KnownHostFingerprint supplied; this test cannot strictly verify the host key. Diagnostics only." `
                -Recommendation "Get the expected fingerprint from WinSCP GUI (Session > Server/Protocol Information) for production use."
        }

        $stdoutPath = Join-Path $OutputDir "stdout.txt"
        $stderrPath = Join-Path $OutputDir "stderr.txt"
        $argList = @("/ini=nul", "/log=`"$sessionLog`"", "/loglevel=$logLevel", "/script=`"$scriptFile`"")

        $proc = Start-Process -FilePath $WinScpComPath -ArgumentList $argList -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

        if ($proc.ExitCode -eq 0) {
            Add-Result -Stage "6-LiveTest" -Check "Connection result" -Status "Pass" -Details "winscp.com exited 0 (success). See $sessionLog for full detail."
        } else {
            Add-Result -Stage "6-LiveTest" -Check "Connection result" -Status "Fail" -Details "winscp.com exited $($proc.ExitCode) (failure). See $sessionLog for full detail."
        }

        if (Test-Path $sessionLog) {
            $logContent = Get-Content $sessionLog -Raw
            $logLines = Get-Content $sessionLog

            $refusedLines = $logLines | Select-String -Pattern "refused|Access denied|Authentication failed" -SimpleMatch:$false
            if ($refusedLines) {
                $sample = ($refusedLines | Select-Object -First 5 | ForEach-Object { $_.Line }) -join " | "
                Add-Result -Stage "6-LiveTest" -Check "Refusal detected in log" -Status "Fail" -Details $sample
                Add-Signal -Cause "Server explicitly refused the offered key/auth attempt" -Weight 25 -Evidence $sample
            }

            $algoLines = $logLines | Select-String -Pattern "We claim version|Server version|kex algos|server->client|client->server|Using .* to encrypt|Offer of public key"
            if ($algoLines) {
                $algoSample = ($algoLines | Select-Object -First 15 | ForEach-Object { $_.Line }) -join "`n"
                Add-Result -Stage "6-LiveTest" -Check "Negotiation detail (algorithms)" -Status "Info" -Details $algoSample
            }

            if ($logContent -match "ssh-rsa" -and $Script:DetectedKeyType -eq "ssh-rsa") {
                if ($logContent -match "no matching (host key type|signature algorithm)" -or $logContent -match "Couldn't agree") {
                    Add-Result -Stage "6-LiveTest" -Check "Algorithm agreement" -Status "Fail" `
                        -Details "Log shows an algorithm agreement failure involving ssh-rsa signatures." `
                        -Recommendation "Confirms the legacy-algorithm theory. Upgrade the WinSCP build (Stage 2) so it offers rsa-sha2-256/512 for this same key, or ask the server to explicitly re-enable ssh-rsa via PubkeyAcceptedAlgorithms (less preferred, weaker security)."
                    Add-Signal -Cause "Confirmed: ssh-rsa signature algorithm rejected during negotiation" -Weight 50 -Evidence "Log contains algorithm agreement failure referencing ssh-rsa"
                }
            }
        }
    } catch {
        Add-Result -Stage "6-LiveTest" -Check "Live connection test" -Status "Fail" -Details $_.Exception.Message
    }
}

# ======================================================================
# STAGE 7 - Root-cause correlation and confidence scoring
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 7: Root-Cause Analysis =====" -ForegroundColor Cyan
$rootCauses = $Script:Signals | Group-Object Cause | ForEach-Object {
    [PSCustomObject]@{
        Cause    = $_.Name
        Score    = ($_.Group | Measure-Object -Property Weight -Sum).Sum
        Evidence = ($_.Group | ForEach-Object { $_.Evidence }) -join " | "
    }
} | Sort-Object Score -Descending

if ($rootCauses.Count -eq 0) {
    Add-Result -Stage "7-RootCause" -Check "Correlation" -Status "Info" -Details "No strong signals collected; review Stage 1-6 details individually."
} else {
    $maxScore = ($rootCauses | Measure-Object -Property Score -Maximum).Maximum
    foreach ($rc in $rootCauses) {
        $pct = if ($maxScore -gt 0) { [math]::Round(($rc.Score / $maxScore) * 100) } else { 0 }
        Add-Result -Stage "7-RootCause" -Check $rc.Cause -Status "Info" -Details "Confidence score: $($rc.Score) ($pct% relative) - Evidence: $($rc.Evidence)"
    }
}
$Script:RootCauses = $rootCauses

# ======================================================================
# STAGE 8 - HTML report generation
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 8: Generating HTML Report =====" -ForegroundColor Cyan

function Get-StatusBadge($status) {
    switch ($status) {
        "Pass" { return "<span class='badge badge-pass'>PASS</span>" }
        "Warn" { return "<span class='badge badge-warn'>WARN</span>" }
        "Fail" { return "<span class='badge badge-fail'>FAIL</span>" }
        default { return "<span class='badge badge-info'>INFO</span>" }
    }
}

function HtmlEncode($text) {
    if ($null -eq $text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$text)
}

$passCount = ($Script:Results | Where-Object Status -eq "Pass").Count
$warnCount = ($Script:Results | Where-Object Status -eq "Warn").Count
$failCount = ($Script:Results | Where-Object Status -eq "Fail").Count
$infoCount = ($Script:Results | Where-Object Status -eq "Info").Count

$rootCauseHtml = ""
if ($Script:RootCauses -and $Script:RootCauses.Count -gt 0) {
    $maxScore = ($Script:RootCauses | Measure-Object -Property Score -Maximum).Maximum
    $rows = foreach ($rc in $Script:RootCauses) {
        $pct = if ($maxScore -gt 0) { [math]::Round(($rc.Score / $maxScore) * 100) } else { 0 }
        @"
        <div class="cause-row">
          <div class="cause-label">$(HtmlEncode $rc.Cause)</div>
          <div class="cause-bar-track"><div class="cause-bar-fill" style="width:$pct%;"></div></div>
          <div class="cause-score">$pct%</div>
        </div>
        <div class="cause-evidence">Evidence: $(HtmlEncode $rc.Evidence)</div>
"@
    }
    $rootCauseHtml = $rows -join "`n"
} else {
    $rootCauseHtml = "<p>No dominant root-cause signal detected. Review each stage below individually.</p>"
}

$stageOrder = @("1-Context","2-WinSCP","3-PrivateKey","4-PublicKey","5-Network","6-LiveTest","7-RootCause")
$stagesHtml = foreach ($stage in $stageOrder) {
    $items = $Script:Results | Where-Object { $_.Stage -eq $stage }
    if (-not $items) { continue }
    $stageTitle = switch ($stage) {
        "1-Context"    { "Stage 1 - Execution Context" }
        "2-WinSCP"     { "Stage 2 - WinSCP Installation Audit" }
        "3-PrivateKey" { "Stage 3 - Private Key Analysis" }
        "4-PublicKey"  { "Stage 4 - Public Key Analysis" }
        "5-Network"    { "Stage 5 - Network & SSH Banner" }
        "6-LiveTest"   { "Stage 6 - Live Connection Test" }
        "7-RootCause"  { "Stage 7 - Root-Cause Correlation" }
    }
    $rowsHtml = foreach ($item in $items) {
        $recRow = ""
        if ($item.Recommendation) {
            $recRow = "<div class='rec'><strong>Recommendation:</strong> $(HtmlEncode $item.Recommendation)</div>"
        }
        @"
        <div class="check-row status-$($item.Status.ToLower())">
          <div class="check-head">
            $(Get-StatusBadge $item.Status)
            <span class="check-name">$(HtmlEncode $item.Check)</span>
            <span class="check-time">$($item.Timestamp)</span>
          </div>
          <div class="check-detail">$(HtmlEncode $item.Details)</div>
          $recRow
        </div>
"@
    }
    @"
    <details class="stage" open>
      <summary>$stageTitle <span class="count">($($items.Count) checks)</span></summary>
      <div class="stage-body">
        $($rowsHtml -join "`n")
      </div>
    </details>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SFTP Diagnostic Report - $(HtmlEncode $SftpHost)</title>
<style>
  :root {
    --bg: #0f1420; --panel: #161d2e; --border: #263049; --text: #e6e9f0; --muted: #8b93a7;
    --pass: #2fbf71; --warn: #e6b422; --fail: #e5484d; --info: #4a90e2; --accent: #7c9eff;
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 0; padding: 32px; line-height: 1.5; }
  h1 { font-size: 22px; margin-bottom: 4px; }
  .subtitle { color: var(--muted); font-size: 14px; margin-bottom: 24px; }
  .summary-bar { display: flex; gap: 12px; margin-bottom: 28px; flex-wrap: wrap; }
  .summary-chip { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 10px 16px; font-size: 14px; }
  .summary-chip b { font-size: 18px; display: block; }
  .chip-pass b { color: var(--pass); } .chip-warn b { color: var(--warn); }
  .chip-fail b { color: var(--fail); } .chip-info b { color: var(--info); }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 20px 24px; margin-bottom: 24px; }
  .panel h2 { margin-top: 0; font-size: 16px; color: var(--accent); }
  .cause-row { display: flex; align-items: center; gap: 12px; margin-top: 10px; }
  .cause-label { width: 380px; font-size: 13px; }
  .cause-bar-track { flex: 1; background: #1e2740; border-radius: 6px; height: 10px; overflow: hidden; }
  .cause-bar-fill { background: linear-gradient(90deg, var(--fail), var(--warn)); height: 100%; }
  .cause-score { width: 40px; text-align: right; font-size: 12px; color: var(--muted); }
  .cause-evidence { font-size: 11px; color: var(--muted); margin: 2px 0 12px 0; padding-left: 4px; }
  details.stage { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 14px; padding: 4px 0; }
  details.stage > summary { cursor: pointer; padding: 14px 20px; font-size: 15px; font-weight: 600; list-style: none; }
  details.stage > summary::-webkit-details-marker { display: none; }
  details.stage > summary::before { content: "▸ "; color: var(--accent); }
  details.stage[open] > summary::before { content: "▾ "; }
  .count { color: var(--muted); font-weight: 400; font-size: 13px; }
  .stage-body { padding: 0 20px 16px 20px; }
  .check-row { border-top: 1px solid var(--border); padding: 12px 0; }
  .check-head { display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }
  .check-name { font-weight: 600; font-size: 14px; }
  .check-time { margin-left: auto; color: var(--muted); font-size: 11px; }
  .check-detail { font-size: 13px; color: #c4c9d6; white-space: pre-wrap; word-break: break-word; }
  .rec { margin-top: 6px; font-size: 12px; background: #1c2338; border-left: 3px solid var(--accent); padding: 8px 10px; border-radius: 4px; color: #b9c2d8; }
  .badge { font-size: 10px; font-weight: 700; padding: 3px 8px; border-radius: 20px; letter-spacing: 0.5px; }
  .badge-pass { background: rgba(47,191,113,0.15); color: var(--pass); }
  .badge-warn { background: rgba(230,180,34,0.15); color: var(--warn); }
  .badge-fail { background: rgba(229,72,77,0.15); color: var(--fail); }
  .badge-info { background: rgba(74,144,226,0.15); color: var(--info); }
  .status-fail { border-left: 3px solid var(--fail); padding-left: 12px; margin-left: -12px; }
  .status-warn { border-left: 3px solid var(--warn); padding-left: 12px; margin-left: -12px; }
  footer { color: var(--muted); font-size: 11px; margin-top: 30px; }
</style>
</head>
<body>

<h1>SFTP Connection Diagnostic Report</h1>
<div class="subtitle">Target: $(HtmlEncode $SftpHost):$SftpPort &nbsp;|&nbsp; User: $(HtmlEncode $Username) &nbsp;|&nbsp; Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>

<div class="summary-bar">
  <div class="summary-chip chip-pass"><b>$passCount</b>Passed</div>
  <div class="summary-chip chip-warn"><b>$warnCount</b>Warnings</div>
  <div class="summary-chip chip-fail"><b>$failCount</b>Failed</div>
  <div class="summary-chip chip-info"><b>$infoCount</b>Info</div>
</div>

<div class="panel">
  <h2>Likely Root Causes (ranked by confidence)</h2>
  $rootCauseHtml
</div>

$($stagesHtml -join "`n")

<footer>
  Generated by Invoke-SftpDiagnostics.ps1 &nbsp;|&nbsp; Logs and raw script: $OutputDir<br/>
  $(if ($EnablePasswordLogging) { "WARNING: password logging was enabled for this run - delete the session log after review." } else { "" })
</footer>

</body>
</html>
"@

$htmlPath = Join-Path $OutputDir "SftpDiagnosticReport.html"
$html | Set-Content -Path $htmlPath -Encoding UTF8

Write-Host ""
Write-Host "======================================================" -ForegroundColor Green
Write-Host " Report generated: $htmlPath" -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Opening report..." -ForegroundColor Cyan
try { Start-Process $htmlPath } catch { Write-Host "Could not auto-open; open the file manually." -ForegroundColor Yellow }

if ($EnablePasswordLogging) {
    Write-Host ""
    Write-Host "SECURITY REMINDER: $sessionLog may contain your password in plaintext" -ForegroundColor Red
    Write-Host "(debug level 2* logging). Delete it once you're done reviewing:" -ForegroundColor Red
    Write-Host "  Remove-Item '$sessionLog'" -ForegroundColor Red
}
