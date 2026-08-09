<#
.SYNOPSIS
    Parses an OpenSSH .pub file and reports its key type, bit length, and
    fingerprints (SHA256 and MD5) — without relying on ssh-keygen.exe.

.PARAMETER Path
    Path to the .pub file (standard OpenSSH single-line format:
    "<type> <base64-blob> [comment]").

.EXAMPLE
    .\Get-PublicKeyDetails.ps1 -Path "C:\keys\myserver.pub"
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

if (-not (Test-Path $Path)) {
    Write-Host "File not found: $Path" -ForegroundColor Red
    return
}

$line = (Get-Content $Path -TotalCount 1).Trim()
$parts = $line -split '\s+', 3

if ($parts.Count -lt 2) {
    Write-Host "Doesn't look like a standard OpenSSH .pub file (expected '<type> <base64> [comment]')." -ForegroundColor Red
    Write-Host "First line was: $line"
    return
}

$keyType = $parts[0]
$b64     = $parts[1]
$comment = if ($parts.Count -ge 3) { $parts[2] } else { "" }

try {
    $blob = [Convert]::FromBase64String($b64)
} catch {
    Write-Host "Could not base64-decode the key blob. Is this really a .pub file?" -ForegroundColor Red
    return
}

# ---- Walk the SSH wire-format fields (each is: 4-byte big-endian length + data) ----
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

$offset = 0
$typeField = Read-SshField -Bytes $blob -Offset ([ref]$offset)
$typeStr = [System.Text.Encoding]::ASCII.GetString($typeField)

$bitLength = "unknown"
switch -Wildcard ($typeStr) {
    "ssh-rsa" {
        $e = Read-SshField -Bytes $blob -Offset ([ref]$offset)   # public exponent (unused here)
        $n = Read-SshField -Bytes $blob -Offset ([ref]$offset)   # modulus
        # mpint may have a leading 0x00 sign byte; strip it, then count bits of the top byte
        $nBytes = $n
        if ($nBytes.Length -gt 0 -and $nBytes[0] -eq 0) { $nBytes = $nBytes[1..($nBytes.Length - 1)] }
        $bits = $nBytes.Length * 8
        $top = $nBytes[0]
        for ($b = 7; $b -ge 0; $b--) {
            if (($top -band (1 -shl $b)) -eq 0) { $bits-- } else { break }
        }
        $bitLength = $bits
    }
    "ssh-ed25519" {
        Read-SshField -Bytes $blob -Offset ([ref]$offset) | Out-Null  # 32-byte public key
        $bitLength = 256
    }
    "ecdsa-sha2-*" {
        $curve = Read-SshField -Bytes $blob -Offset ([ref]$offset)
        $curveStr = [System.Text.Encoding]::ASCII.GetString($curve)
        $bitLength = switch ($curveStr) {
            "nistp256" { 256 }
            "nistp384" { 384 }
            "nistp521" { 521 }
            default    { "unknown ($curveStr)" }
        }
    }
    default {
        $bitLength = "unknown (unrecognized type: $typeStr)"
    }
}

# ---- Fingerprints ----
$sha256 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($blob)
$sha256b64 = [Convert]::ToBase64String($sha256).TrimEnd('=')   # ssh-keygen strips the padding
$sha256Fingerprint = "SHA256:$sha256b64"

$md5 = [System.Security.Cryptography.MD5]::Create().ComputeHash($blob)
$md5Fingerprint = ($md5 | ForEach-Object { $_.ToString("x2") }) -join ':'

# ---- Output ----
Write-Host ""
Write-Host "File          : $Path"
Write-Host "Key type      : $typeStr"
Write-Host "Bit length    : $bitLength"
Write-Host "Comment       : $(if ($comment) { $comment } else { '(none)' })"
Write-Host "SHA256 fingerprint : $sha256Fingerprint"
Write-Host "MD5 fingerprint    : $md5Fingerprint"
Write-Host ""

if ($typeStr -eq "ssh-rsa") {
    Write-Host "NOTE: this is an RSA key using the 'ssh-rsa' type name, which implies" -ForegroundColor Yellow
    Write-Host "the legacy ssh-rsa/SHA-1 signature algorithm during authentication." -ForegroundColor Yellow
    Write-Host "Many OpenSSH servers (8.8+) now reject this by default unless" -ForegroundColor Yellow
    Write-Host "PubkeyAcceptedAlgorithms explicitly re-enables it, or unless the client" -ForegroundColor Yellow
    Write-Host "renegotiates using rsa-sha2-256/512 (same key, different signature alg)." -ForegroundColor Yellow
    Write-Host "This is worth flagging to your SFTP server admin directly." -ForegroundColor Yellow
}

Write-Host "To compare against the server's authorized_keys, ask the admin to run:" -ForegroundColor Cyan
Write-Host "  ssh-keygen -lf ~/.ssh/authorized_keys" -ForegroundColor Cyan
Write-Host "and check whether the SHA256 fingerprint above appears in the output." -ForegroundColor Cyan
