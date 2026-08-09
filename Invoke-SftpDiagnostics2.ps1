<#
.SYNOPSIS
    Staged SFTP "Server refused the key" diagnostic tool - independent of any
    WinSCP GUI baseline. Cross-tests via native OpenSSH (ssh.exe -vvv) AND
    winscp.com, and compares the two outcomes to isolate whether the problem
    is client-specific (WinSCP build/config) or server/key/credential-specific.
    Produces a detailed HTML report.

.DESCRIPTION
    Stage 1 - Execution context
    Stage 2 - Tool inventory (winscp.com, ssh.exe, puttygen.exe - informational, no baseline comparison)
    Stage 3 - Private key analysis (format, ACL) + auto-convert to OpenSSH format for native testing if needed
    Stage 4 - Public key analysis (type, bit length, fingerprints)
    Stage 5 - Network reachability + raw SSH banner grab (no auth attempted)
    Stage 6 - Native ssh.exe -vvv authentication test (tool-agnostic ground truth)
    Stage 7 - winscp.com authentication test (what your automation actually uses)
    Stage 8 - Cross-tool comparison (isolates client-side vs server/key-side cause)
    Stage 9 - Root-cause correlation and confidence scoring
    Stage 10 - HTML report generation

.PARAMETER SftpHost
    SFTP server hostname or IP.
.PARAMETER SftpPort
    SFTP server port (default 22).
.PARAMETER Username
    SFTP username.
.PARAMETER Password
    SFTP password. Leave blank for key-only auth.
.PARAMETER PrivateKeyPath
    Path to the private key (.ppk or OpenSSH format) used by your automation.
.PARAMETER PublicKeyPath
    Optional path to the matching .pub file, for key-type/fingerprint analysis.
.PARAMETER KnownHostFingerprint
    Expected SSH host key fingerprint (WinSCP-format, e.g. from Session > Server
    Information, or "ssh-ed25519 255 xx:xx:...:xx"). Optional; if omitted, the
    winscp.com test skips strict host key checking (diagnostics only).
.PARAMETER WinScpComPath
    Full path to the winscp.com your automation invokes.
.PARAMETER SshExePath
    Path to ssh.exe. Defaults to the built-in Windows OpenSSH client if present.
.PARAMETER PuttygenPath
    Path to puttygen.exe, used only to convert a .ppk key to OpenSSH format for
    the native ssh.exe test. Auto-detected next to winscp.com's folder if omitted.
.PARAMETER EnablePasswordLogging
    Enables WinSCP /loglevel=2* (password appears in plaintext in the log).
.PARAMETER OutputDir
    Where logs and the HTML report are written.

.EXAMPLE
    .\Invoke-SftpDiagnostics2.ps1 -SftpHost sftp.example.com -Username svc_transfer `
        -PrivateKeyPath "C:\keys\transfer.ppk" -PublicKeyPath "C:\keys\transfer.pub" `
        -WinScpComPath "C:\Automation\winscp.com"
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
    [string]$SshExePath = "$env:WINDIR\System32\OpenSSH\ssh.exe",
    [string]$PuttygenPath = "",
    [switch]$EnablePasswordLogging,
    [string]$OutputDir = "$env:TEMP\SftpDiag_$(Get-Date -Format yyyyMMdd_HHmmss)"
)

$Script:Results = New-Object System.Collections.Generic.List[Object]
$Script:Signals  = New-Object System.Collections.Generic.List[Object]

function Add-Result {
    param(
        [string]$Stage, [string]$Check,
        [ValidateSet("Pass","Warn","Fail","Info")][string]$Status,
        [string]$Details, [string]$Recommendation = ""
    )
    $Script:Results.Add([PSCustomObject]@{
        Stage = $Stage; Check = $Check; Status = $Status; Details = $Details
        Recommendation = $Recommendation; Timestamp = (Get-Date -Format "HH:mm:ss")
    })
    $color = switch ($Status) { "Pass" {"Green"} "Warn" {"Yellow"} "Fail" {"Red"} default {"Gray"} }
    Write-Host "[$Stage] $Check : $Status - $Details" -ForegroundColor $color
}

function Add-Signal {
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
    Add-Result -Stage "1-Context" -Check "Running as" -Status "Info" -Details "$whoAmI (interactive: $([Environment]::UserInteractive))"
    Add-Result -Stage "1-Context" -Check "PowerShell version" -Status "Info" -Details $PSVersionTable.PSVersion.ToString()
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($osInfo) { Add-Result -Stage "1-Context" -Check "OS" -Status "Info" -Details "$($osInfo.Caption) (Build $($osInfo.BuildNumber))" }
    if ($whoAmI -match '\\(svc|service|system)') {
        Add-Result -Stage "1-Context" -Check "Service account pattern" -Status "Warn" `
            -Details "Account name suggests a service/scheduled-task identity." `
            -Recommendation "Confirm this account can read the key file and has any needed profile-scoped SSH config (known_hosts, etc.)."
    }
} catch {
    Add-Result -Stage "1-Context" -Check "Context collection" -Status "Fail" -Details $_.Exception.Message
}

# ======================================================================
# STAGE 2 - Tool inventory (informational only - no GUI baseline comparison)
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 2: Tool Inventory =====" -ForegroundColor Cyan
$Script:HaveSsh = $false
$Script:HaveWinScp = $false

if (Test-Path $WinScpComPath) {
    $comVersion = (Get-Item $WinScpComPath).VersionInfo.FileVersion
    Add-Result -Stage "2-Tools" -Check "winscp.com" -Status "Pass" -Details "$WinScpComPath (version $comVersion)"
    $Script:HaveWinScp = $true
} else {
    Add-Result -Stage "2-Tools" -Check "winscp.com" -Status "Fail" -Details "Not found at: $WinScpComPath" `
        -Recommendation "Verify the exact path your automation invokes."
    Add-Signal -Cause "winscp.com path invalid/missing" -Weight 40 -Evidence "Configured path not found: $WinScpComPath"
}

$resolvedSsh = $null
if (Test-Path $SshExePath) { $resolvedSsh = $SshExePath }
else {
    $cmd = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if ($cmd) { $resolvedSsh = $cmd.Source }
}
if ($resolvedSsh) {
    $sshVerOutput = & $resolvedSsh -V 2>&1 | Out-String
    Add-Result -Stage "2-Tools" -Check "Native ssh.exe" -Status "Pass" -Details "$resolvedSsh - $($sshVerOutput.Trim())"
    $Script:SshExePath = $resolvedSsh
    $Script:HaveSsh = $true
} else {
    Add-Result -Stage "2-Tools" -Check "Native ssh.exe" -Status "Warn" -Details "Not found (checked $SshExePath and PATH)." `
        -Recommendation "Install the Windows OpenSSH Client feature for an independent, tool-agnostic test: Settings > Optional Features > OpenSSH Client."
}

if ([string]::IsNullOrWhiteSpace($PuttygenPath)) {
    $candidates = @(
        (Join-Path (Split-Path $WinScpComPath -ErrorAction SilentlyContinue) "PuTTYgen.exe"),
        "$env:ProgramFiles\WinSCP\PuTTYgen.exe",
        "${env:ProgramFiles(x86)}\WinSCP\PuTTYgen.exe"
    )
    $PuttygenPath = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
if ($PuttygenPath -and (Test-Path $PuttygenPath)) {
    Add-Result -Stage "2-Tools" -Check "puttygen.exe" -Status "Info" -Details "$PuttygenPath (used only if key needs .ppk -> OpenSSH conversion for the native test)"
} else {
    Add-Result -Stage "2-Tools" -Check "puttygen.exe" -Status "Info" -Details "Not found. If your key is .ppk format, native ssh.exe test may be skipped unless an OpenSSH-format key is available."
}

$poshSsh = Get-Module -ListAvailable -Name Posh-SSH -ErrorAction SilentlyContinue
if ($poshSsh) {
    Add-Result -Stage "2-Tools" -Check "Posh-SSH module" -Status "Info" -Details "Available (v$($poshSsh[0].Version)) - not used by this script, noted for reference."
}

# ======================================================================
# STAGE 3 - Private key analysis + auto-prepare OpenSSH-format copy
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 3: Private Key Analysis =====" -ForegroundColor Cyan
$Script:NativeTestKeyPath = $null
$Script:KeyIsPpk = $false

if (Test-Path $PrivateKeyPath) {
    Add-Result -Stage "3-PrivateKey" -Check "File exists" -Status "Pass" -Details $PrivateKeyPath
    $firstLines = Get-Content $PrivateKeyPath -TotalCount 3

    if ($firstLines -match "PuTTY-User-Key-File-3") {
        Add-Result -Stage "3-PrivateKey" -Check "Format" -Status "Info" -Details "PuTTY PPK v3."
        $Script:KeyIsPpk = $true
    } elseif ($firstLines -match "PuTTY-User-Key-File-2") {
        Add-Result -Stage "3-PrivateKey" -Check "Format" -Status "Info" -Details "PuTTY PPK v2."
        $Script:KeyIsPpk = $true
    } elseif ($firstLines -match "BEGIN OPENSSH PRIVATE KEY|BEGIN RSA PRIVATE KEY|BEGIN EC PRIVATE KEY") {
        Add-Result -Stage "3-PrivateKey" -Check "Format" -Status "Pass" -Details "Already OpenSSH/PEM format - usable directly by native ssh.exe."
        $Script:NativeTestKeyPath = $PrivateKeyPath
    } else {
        Add-Result -Stage "3-PrivateKey" -Check "Format" -Status "Warn" -Details "Unrecognized header; verify this is really a private key."
    }

    try {
        $acl = Get-Acl $PrivateKeyPath
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $entries = $acl.Access | Where-Object { $_.IdentityReference -eq $currentUser -or $_.IdentityReference -match "Everyone|Authenticated Users|Users" }
        if ($entries) {
            $summary = ($entries | ForEach-Object { "$($_.IdentityReference): $($_.FileSystemRights)" }) -join "; "
            Add-Result -Stage "3-PrivateKey" -Check "ACL for current identity" -Status "Info" -Details $summary
        } else {
            Add-Result -Stage "3-PrivateKey" -Check "ACL for current identity" -Status "Warn" `
                -Details "Current identity ($currentUser) not explicitly in ACL - relying on inherited/group permissions." `
                -Recommendation "If the automation runs as a different account, verify THAT account can read this exact file."
        }
    } catch {
        Add-Result -Stage "3-PrivateKey" -Check "ACL check" -Status "Warn" -Details "Could not read ACL: $($_.Exception.Message)"
    }

    # Convert PPK -> OpenSSH so the native ssh.exe test can use the SAME key material
    if ($Script:KeyIsPpk -and $Script:HaveSsh -and $PuttygenPath -and (Test-Path $PuttygenPath)) {
        try {
            $convertedPath = Join-Path $OutputDir "diag_key_openssh"
            & $PuttygenPath $PrivateKeyPath -O private-openssh -o $convertedPath 2>&1 | Out-Null
            if (Test-Path $convertedPath) {
                icacls $convertedPath /inheritance:r | Out-Null
                icacls $convertedPath /grant:r "$($env:USERNAME):(R)" | Out-Null
                $Script:NativeTestKeyPath = $convertedPath
                Add-Result -Stage "3-PrivateKey" -Check "PPK -> OpenSSH conversion" -Status "Pass" `
                    -Details "Converted to $convertedPath for the native ssh.exe test (same key material, different encoding)."
            } else {
                Add-Result -Stage "3-PrivateKey" -Check "PPK -> OpenSSH conversion" -Status "Warn" -Details "puttygen did not produce an output file; native test will be skipped."
            }
        } catch {
            Add-Result -Stage "3-PrivateKey" -Check "PPK -> OpenSSH conversion" -Status "Warn" -Details "Conversion failed: $($_.Exception.Message)"
        }
    } elseif ($Script:KeyIsPpk -and -not $Script:NativeTestKeyPath) {
        Add-Result -Stage "3-PrivateKey" -Check "PPK -> OpenSSH conversion" -Status "Warn" `
            -Details "Key is .ppk and no puttygen.exe available to convert it." `
            -Recommendation "Native ssh.exe test (Stage 6) will be skipped without a converted key. Supply -PuttygenPath if it's installed elsewhere."
    }
} else {
    Add-Result -Stage "3-PrivateKey" -Check "File exists" -Status "Fail" -Details "Not found: $PrivateKeyPath"
    Add-Signal -Cause "Private key inaccessible/missing in this context" -Weight 45 -Evidence "Path not found: $PrivateKeyPath"
}

# ======================================================================
# STAGE 4 - Public key analysis
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
            Read-SshField -Bytes $blob -Offset ([ref]$offset) | Out-Null

            $bitLength = "unknown"
            if ($keyType -eq "ssh-rsa") {
                Read-SshField -Bytes $blob -Offset ([ref]$offset) | Out-Null
                $n = Read-SshField -Bytes $blob -Offset ([ref]$offset)
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
                -Recommendation "Ask the server admin to confirm this exact fingerprint is present in authorized_keys (ssh-keygen -lf ~/.ssh/authorized_keys)."

            if ($keyType -eq "ssh-rsa") {
                Add-Result -Stage "4-PublicKey" -Check "Algorithm exposure" -Status "Warn" `
                    -Details "Key type 'ssh-rsa' implies possible use of the legacy ssh-rsa/SHA-1 signature algorithm during auth." `
                    -Recommendation "If the server disabled ssh-rsa/SHA-1 signatures recently, an older/limited client will be refused even with a valid, authorized key."
                Add-Signal -Cause "RSA key using legacy signature algorithm rejected by hardened server" -Weight 30 -Evidence "Public key type is ssh-rsa ($bitLength bits)"
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
            -Recommendation "Resolve network/firewall reachability before investigating SSH-level causes further."
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
        $stream = $client.GetStream(); $stream.ReadTimeout = 5000
        $buffer = New-Object byte[] 256
        $read = $stream.Read($buffer, 0, 256)
        $banner = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read).Trim()
        $client.Close()
        Add-Result -Stage "5-Network" -Check "SSH server banner" -Status "Info" -Details $banner

        if ($banner -match "OpenSSH_(\d+)\.(\d+)") {
            $major = [int]$Matches[1]; $minor = [int]$Matches[2]
            if ($major -gt 8 -or ($major -eq 8 -and $minor -ge 8)) {
                Add-Result -Stage "5-Network" -Check "Server OpenSSH version policy" -Status "Warn" `
                    -Details "Server reports OpenSSH $major.$minor. OpenSSH 8.8+ disables legacy ssh-rsa/SHA-1 signatures by default." `
                    -Recommendation "Consistent with sudden key refusals after a server-side OpenSSH upgrade/patch, if your key/client offers ssh-rsa."
                Add-Signal -Cause "Server OpenSSH version disables legacy ssh-rsa signatures by default" -Weight 25 -Evidence "Banner: $banner"
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
# STAGE 6 - Native ssh.exe -vvv authentication test (tool-agnostic ground truth)
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 6: Native SSH Test (ssh.exe) =====" -ForegroundColor Cyan
$Script:NativeSshSuccess = $null   # $null = not run, $true/$false = result
$nativeLog = Join-Path $OutputDir "native_ssh_verbose.log"

if (-not $Script:HaveSsh) {
    Add-Result -Stage "6-NativeSSH" -Check "Native SSH test" -Status "Info" -Details "Skipped - ssh.exe not available (see Stage 2)."
} elseif (-not $Script:NativeTestKeyPath) {
    Add-Result -Stage "6-NativeSSH" -Check "Native SSH test" -Status "Info" -Details "Skipped - no OpenSSH-format key available (see Stage 3)."
} else {
    try {
        $stdoutPath = Join-Path $OutputDir "native_ssh_stdout.txt"
        $sshArgs = @(
            "-vvv",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=NUL",
            "-o", "PreferredAuthentications=publickey",
            "-o", "ConnectTimeout=10",
            "-i", $Script:NativeTestKeyPath,
            "-p", $SftpPort,
            "$Username@$SftpHost",
            "exit"
        )
        $proc = Start-Process -FilePath $Script:SshExePath -ArgumentList $sshArgs -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $nativeLog

        $logText = if (Test-Path $nativeLog) { Get-Content $nativeLog -Raw } else { "" }

        if ($proc.ExitCode -eq 0 -or $logText -match 'Authenticated to .* using "publickey"') {
            $Script:NativeSshSuccess = $true
            Add-Result -Stage "6-NativeSSH" -Check "Authentication result" -Status "Pass" `
                -Details "Native ssh.exe authenticated successfully using publickey. This is strong evidence the key IS valid and authorized on the server, independent of WinSCP entirely."
        } else {
            $Script:NativeSshSuccess = $false
            $reason = "Exit code $($proc.ExitCode)."
            if ($logText -match "Permission denied") { $reason += " Log shows 'Permission denied' during publickey auth." }
            if ($logText -match "no matching (host key type|signature algorithm|key exchange method) found") {
                $algoLine = ($logText -split "`n" | Select-String "no matching" | Select-Object -First 1).Line
                $reason += " Algorithm negotiation failure: $algoLine"
                Add-Signal -Cause "SSH algorithm negotiation failure (client/server cannot agree)" -Weight 45 -Evidence $algoLine
            }
            Add-Result -Stage "6-NativeSSH" -Check "Authentication result" -Status "Fail" -Details $reason `
                -Recommendation "See $nativeLog for the full verbose (-vvv) trace. Since this bypasses WinSCP entirely, a failure here points to the key/server/credentials, not to WinSCP's implementation."
            Add-Signal -Cause "Key rejected independent of WinSCP (server/key/credential issue)" -Weight 40 -Evidence $reason
        }

        # Pull out the most informative lines regardless of outcome
        $keyLines = (Get-Content $nativeLog -ErrorAction SilentlyContinue) | Select-String -Pattern "Offering public key|Server accepts key|Authentications that can continue|debug1: Next authentication method|kex_input_ext_info|Skipping .* key" -SimpleMatch:$false
        if ($keyLines) {
            $sample = ($keyLines | Select-Object -First 12 | ForEach-Object { $_.Line }) -join "`n"
            Add-Result -Stage "6-NativeSSH" -Check "Negotiation detail" -Status "Info" -Details $sample
        }
    } catch {
        Add-Result -Stage "6-NativeSSH" -Check "Native SSH test" -Status "Fail" -Details $_.Exception.Message
    }
}

# ======================================================================
# STAGE 7 - winscp.com authentication test (what the automation actually uses)
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 7: WinSCP.com Test =====" -ForegroundColor Cyan
$Script:WinScpSuccess = $null
$sessionLog = Join-Path $OutputDir "winscp_session.log"
$scriptFile = Join-Path $OutputDir "diag_script.txt"
$logLevel = if ($EnablePasswordLogging) { "2*" } else { "2" }

if (-not $Script:HaveWinScp) {
    Add-Result -Stage "7-WinSCP" -Check "WinSCP test" -Status "Info" -Details "Skipped - winscp.com not available (see Stage 2)."
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
            Add-Result -Stage "7-WinSCP" -Check "Host key verification" -Status "Warn" `
                -Details "No -KnownHostFingerprint supplied; host key not strictly verified in this test. Diagnostics only."
        }

        $stdoutPath = Join-Path $OutputDir "winscp_stdout.txt"
        $stderrPath = Join-Path $OutputDir "winscp_stderr.txt"
        $argList = @("/ini=nul", "/log=`"$sessionLog`"", "/loglevel=$logLevel", "/script=`"$scriptFile`"")
        $proc = Start-Process -FilePath $WinScpComPath -ArgumentList $argList -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath

        if ($proc.ExitCode -eq 0) {
            $Script:WinScpSuccess = $true
            Add-Result -Stage "7-WinSCP" -Check "Connection result" -Status "Pass" -Details "winscp.com exited 0 (success)."
        } else {
            $Script:WinScpSuccess = $false
            Add-Result -Stage "7-WinSCP" -Check "Connection result" -Status "Fail" -Details "winscp.com exited $($proc.ExitCode) (failure). See $sessionLog."
        }

        if (Test-Path $sessionLog) {
            $logLines = Get-Content $sessionLog
            $refusedLines = $logLines | Select-String -Pattern "refused|Access denied|Authentication failed" -SimpleMatch:$false
            if ($refusedLines) {
                $sample = ($refusedLines | Select-Object -First 5 | ForEach-Object { $_.Line }) -join " | "
                Add-Result -Stage "7-WinSCP" -Check "Refusal detected in log" -Status "Fail" -Details $sample
                Add-Signal -Cause "WinSCP-reported refusal during authentication" -Weight 20 -Evidence $sample
            }
            $algoLines = $logLines | Select-String -Pattern "We claim version|Server version|kex algos|Offer of public key"
            if ($algoLines) {
                $algoSample = ($algoLines | Select-Object -First 12 | ForEach-Object { $_.Line }) -join "`n"
                Add-Result -Stage "7-WinSCP" -Check "Negotiation detail" -Status "Info" -Details $algoSample
            }
        }
    } catch {
        Add-Result -Stage "7-WinSCP" -Check "WinSCP test" -Status "Fail" -Details $_.Exception.Message
    }
}

# ======================================================================
# STAGE 8 - Cross-tool comparison
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 8: Cross-Tool Comparison =====" -ForegroundColor Cyan

if ($null -eq $Script:NativeSshSuccess -and $null -eq $Script:WinScpSuccess) {
    Add-Result -Stage "8-Compare" -Check "Cross-tool comparison" -Status "Info" -Details "Neither test ran (see Stages 6-7) - nothing to compare."
} elseif ($null -eq $Script:NativeSshSuccess) {
    Add-Result -Stage "8-Compare" -Check "Cross-tool comparison" -Status "Info" -Details "Only winscp.com test ran; native ssh.exe test was skipped. Comparison not possible - see Stage 2/3/6 for why."
} elseif ($null -eq $Script:WinScpSuccess) {
    Add-Result -Stage "8-Compare" -Check "Cross-tool comparison" -Status "Info" -Details "Only native ssh.exe test ran; winscp.com test was skipped."
} elseif ($Script:NativeSshSuccess -and $Script:WinScpSuccess) {
    Add-Result -Stage "8-Compare" -Check "Cross-tool comparison" -Status "Pass" `
        -Details "Both native ssh.exe AND winscp.com succeeded independently with this exact host/user/key." `
        -Recommendation "The key, credentials, and server are all fine right now. If your production automation still fails, the difference must be in HOW it invokes winscp.com: exact open-command syntax/switches, execution account, working directory, timing/concurrency, or a stale cached WinSCP.ini in that context. Compare your production open command line-by-line against this script's."
    Add-Signal -Cause "Environment is currently healthy - likely a script/config mismatch in the real automation, not the server or key" -Weight 20 -Evidence "Both native SSH and winscp.com succeeded in this diagnostic run"
} elseif ($Script:NativeSshSuccess -and -not $Script:WinScpSuccess) {
    Add-Result -Stage "8-Compare" -Check "Cross-tool comparison" -Status "Fail" `
        -Details "Native ssh.exe SUCCEEDED but winscp.com FAILED with the same key, user, and host." `
        -Recommendation "This isolates the problem to WinSCP's own SSH client implementation/build (e.g. an older winscp.com offering a legacy signature algorithm the server now rejects), or to how the open command is constructed. The key itself is proven valid and authorized. Try updating winscp.com to the latest version and re-run this test."
    Add-Signal -Cause "WinSCP-specific issue (client build/negotiation), key itself is valid" -Weight 55 -Evidence "Native SSH succeeded; winscp.com failed with identical credentials"
} else {
    Add-Result -Stage "8-Compare" -Check "Cross-tool comparison" -Status "Fail" `
        -Details "Native ssh.exe FAILED (winscp.com result: $(if($Script:WinScpSuccess){'succeeded'}else{'also failed'}))." `
        -Recommendation "Since this bypasses WinSCP entirely, a native ssh.exe failure points away from WinSCP and toward the key/server/credentials: key not in authorized_keys, key format ssh.exe couldn't parse, server-side algorithm policy, or account/permission issue on the server."
    Add-Signal -Cause "Server/key/credential issue (reproduced without WinSCP)" -Weight 55 -Evidence "Native ssh.exe test failed independent of WinSCP"
}

# ======================================================================
# STAGE 9 - Root-cause correlation and confidence scoring
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 9: Root-Cause Analysis =====" -ForegroundColor Cyan
$rootCauses = $Script:Signals | Group-Object Cause | ForEach-Object {
    [PSCustomObject]@{
        Cause    = $_.Name
        Score    = ($_.Group | Measure-Object -Property Weight -Sum).Sum
        Evidence = ($_.Group | ForEach-Object { $_.Evidence }) -join " | "
    }
} | Sort-Object Score -Descending

if ($rootCauses.Count -eq 0) {
    Add-Result -Stage "9-RootCause" -Check "Correlation" -Status "Info" -Details "No strong signals collected; review each stage individually."
} else {
    $maxScore = ($rootCauses | Measure-Object -Property Score -Maximum).Maximum
    foreach ($rc in $rootCauses) {
        $pct = if ($maxScore -gt 0) { [math]::Round(($rc.Score / $maxScore) * 100) } else { 0 }
        Add-Result -Stage "9-RootCause" -Check $rc.Cause -Status "Info" -Details "Confidence: $pct% - Evidence: $($rc.Evidence)"
    }
}
$Script:RootCauses = $rootCauses

# ======================================================================
# STAGE 10 - HTML report generation
# ======================================================================
Write-Host ""
Write-Host "===== STAGE 10: Generating HTML Report =====" -ForegroundColor Cyan

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

$stageOrder = @("1-Context","2-Tools","3-PrivateKey","4-PublicKey","5-Network","6-NativeSSH","7-WinSCP","8-Compare","9-RootCause")
$stagesHtml = foreach ($stage in $stageOrder) {
    $items = $Script:Results | Where-Object { $_.Stage -eq $stage }
    if (-not $items) { continue }
    $stageTitle = switch ($stage) {
        "1-Context"    { "Stage 1 - Execution Context" }
        "2-Tools"      { "Stage 2 - Tool Inventory" }
        "3-PrivateKey" { "Stage 3 - Private Key Analysis" }
        "4-PublicKey"  { "Stage 4 - Public Key Analysis" }
        "5-Network"    { "Stage 5 - Network & SSH Banner" }
        "6-NativeSSH"  { "Stage 6 - Native SSH Test (ssh.exe)" }
        "7-WinSCP"     { "Stage 7 - WinSCP.com Test" }
        "8-Compare"    { "Stage 8 - Cross-Tool Comparison" }
        "9-RootCause"  { "Stage 9 - Root-Cause Correlation" }
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
  .cause-label { width: 420px; font-size: 13px; }
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
  Generated by Invoke-SftpDiagnostics2.ps1 (WinSCP-GUI-independent, cross-tool version) &nbsp;|&nbsp; Logs: $OutputDir<br/>
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
try { Start-Process $htmlPath } catch { Write-Host "Could not auto-open; open the file manually." -ForegroundColor Yellow }

if ($EnablePasswordLogging) {
    Write-Host ""
    Write-Host "SECURITY REMINDER: $sessionLog may contain your password in plaintext." -ForegroundColor Red
    Write-Host "Delete it once reviewed:  Remove-Item '$sessionLog'" -ForegroundColor Red
}
