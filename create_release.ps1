# Build Windows release binary with embedded CyRecon icon, then create GitHub Release.
# Usage: .\create_release.ps1 -Token <GITHUB_TOKEN>

param(
    [Parameter(Mandatory=$true)]
    [string]$Token,
    
    [string]$Tag = "v1.0.0",
    [string]$Owner = "KaiHT-Ladiant",
    [string]$Repo = "Cyber-OSINT-Recon",
    [string]$ReleaseName = "Release v1.0.0",
    [string]$ReleaseBody = "CyRecon release with Windows AMD64 binary`n`n**Changes:**`n- [Mode] single/multi domain scan`n- Embedded CyRecon application icon`n- Restored CLI entrypoint",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$binaryPath = "Releases\cyber-osint-recon-windows-amd64.exe"
$binaryName = "cyber-osint-recon-windows-amd64.exe"
$iconPath = "assets\cyrecon.ico"
$sysoPath = "cmd\cyber-osint-recon\rsrc_windows_amd64.syso"

if (-not $SkipBuild) {
    if (-not (Test-Path $iconPath)) {
        Write-Host "[!] Icon not found: $iconPath" -ForegroundColor Red
        exit 1
    }

    Write-Host "[+] Embedding CyRecon icon into Windows resources..." -ForegroundColor Yellow
    go run github.com/akavel/rsrc@v0.10.2 -ico $iconPath -arch amd64 -o $sysoPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to generate .syso resource file" -ForegroundColor Red
        exit 1
    }

    New-Item -ItemType Directory -Force -Path "Releases" | Out-Null
    Write-Host "[+] Building Windows AMD64 binary with icon..." -ForegroundColor Yellow
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    go build -o $binaryPath ./cmd/cyber-osint-recon
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Build failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Built: $binaryPath" -ForegroundColor Green
}

if (-not (Test-Path $binaryPath)) {
    Write-Host "[!] Binary file not found: $binaryPath" -ForegroundColor Red
    exit 1
}

# GitHub API URLs
$apiBaseUrl = "https://api.github.com/repos/$Owner/$Repo"
$releaseUrl = "$apiBaseUrl/releases"

Write-Host "[+] Creating GitHub Release for tag: $Tag" -ForegroundColor Green

# Release 생성
$releaseData = @{
    tag_name = $Tag
    name = $ReleaseName
    body = $ReleaseBody
    draft = $false
    prerelease = $false
} | ConvertTo-Json

try {
    $headers = @{
        "Authorization" = "token $Token"
        "Accept" = "application/vnd.github.v3+json"
        "Content-Type" = "application/json"
    }
    
    Write-Host "[+] Creating release..." -ForegroundColor Yellow
    $response = Invoke-RestMethod -Uri $releaseUrl -Method Post -Headers $headers -Body $releaseData
    
    $releaseId = $response.id
    Write-Host "[+] Release created successfully! ID: $releaseId" -ForegroundColor Green
    
    # 바이너리 업로드
    $uploadUrl = $response.upload_url -replace '\{\?name,label\}', "?name=$binaryName"
    
    Write-Host "[+] Uploading binary: $binaryPath" -ForegroundColor Yellow
    $fileBytes = [System.IO.File]::ReadAllBytes($binaryPath)
    $fileEnc = [System.Text.Encoding]::GetEncoding('ISO-8859-1').GetString($fileBytes)
    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"
    
    $bodyLines = (
        "--$boundary",
        "Content-Disposition: form-data; name=`"file`"; filename=`"$binaryName`"",
        "Content-Type: application/octet-stream$LF",
        $fileEnc,
        "--$boundary--"
    ) -join $LF
    
    $uploadHeaders = @{
        "Authorization" = "token $Token"
        "Accept" = "application/vnd.github.v3+json"
        "Content-Type" = "multipart/form-data; boundary=$boundary"
    }
    
    $uploadResponse = Invoke-RestMethod -Uri $uploadUrl -Method Post -Headers $uploadHeaders -Body ([System.Text.Encoding]::GetEncoding('ISO-8859-1').GetBytes($bodyLines))
    
    Write-Host "[+] Binary uploaded successfully!" -ForegroundColor Green
    Write-Host "[+] Release URL: $($response.html_url)" -ForegroundColor Cyan
    
} catch {
    Write-Host "[!] Error: $_" -ForegroundColor Red
    Write-Host "[!] Response: $($_.Exception.Response)" -ForegroundColor Red
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Host "[!] Error details: $responseBody" -ForegroundColor Red
    }
    exit 1
}

Write-Host "[+] Done!" -ForegroundColor Green
