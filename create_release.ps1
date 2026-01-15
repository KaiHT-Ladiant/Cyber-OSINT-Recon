# GitHub Release 생성 스크립트
# 사용법: .\create_release.ps1 -Token <GITHUB_TOKEN>

param(
    [Parameter(Mandatory=$true)]
    [string]$Token,
    
    [string]$Tag = "v1.0.0",
    [string]$Owner = "KaiHT-Ladiant",
    [string]$Repo = "Cyber-OSINT-Recon",
    [string]$ReleaseName = "Release v1.0.0",
    [string]$ReleaseBody = "Initial release with Windows AMD64 binary`n`n**Changes:**`n- Fix: Remove unverified emails and improve deduplication`n- Enhanced email collection and filtering`n- Improved error handling for external services"
)

$ErrorActionPreference = "Stop"

# GitHub API URLs
$apiBaseUrl = "https://api.github.com/repos/$Owner/$Repo"
$releaseUrl = "$apiBaseUrl/releases"
$assetBaseUrl = "$apiBaseUrl/releases"

# 바이너리 파일 경로
$binaryPath = "Releases\cyber-osint-recon-windows-amd64.exe"
$binaryName = "cyber-osint-recon-windows-amd64.exe"

if (-not (Test-Path $binaryPath)) {
    Write-Host "[!] Binary file not found: $binaryPath" -ForegroundColor Red
    exit 1
}

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
