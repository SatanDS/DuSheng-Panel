param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [string]$Repo = "SatanDS/DuSheng-Panel",
  [string]$OutputDir = "release",
  [string]$Commit = "HEAD",
  [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

function Get-GitHubToken {
  if ($env:GH_TOKEN) {
    return $env:GH_TOKEN
  }
  if ($env:GITHUB_TOKEN) {
    return $env:GITHUB_TOKEN
  }

  $credentialInput = "protocol=https`nhost=github.com`n`n"
  $credentialLines = $credentialInput | git credential fill 2>$null
  $passwordLine = $credentialLines | Where-Object { $_ -like "password=*" } | Select-Object -First 1
  if ($passwordLine) {
    return $passwordLine.Substring("password=".Length)
  }

  throw "GitHub token not found. Set GH_TOKEN/GITHUB_TOKEN or login with Git Credential Manager."
}

if ($Version -notmatch "^v") {
  $Version = "v$Version"
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Push-Location $repoRoot
try {
  $targetCommit = (git rev-parse $Commit).Trim()
  if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot "build-agent-release.ps1") -Version $Version -OutputDir $OutputDir -Clean
  }

  $releaseDir = Join-Path $repoRoot $OutputDir
  $requiredAssets = @(
    "dusheng-agent-linux-amd64.tar.gz",
    "dusheng-agent-linux-arm64.tar.gz",
    "checksums.txt"
  )
  foreach ($asset in $requiredAssets) {
    $assetPath = Join-Path $releaseDir $asset
    if (-not (Test-Path -LiteralPath $assetPath)) {
      throw "Missing release asset: $assetPath"
    }
  }

  $token = Get-GitHubToken
  $headers = @{
    Authorization = "Bearer $token"
    Accept = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent" = "DuSheng-Panel-Release"
  }
  $api = "https://api.github.com/repos/$Repo"

  try {
    $release = Invoke-RestMethod -Method Get -Uri "$api/releases/tags/$Version" -Headers $headers
    Write-Host "Release exists: $($release.html_url)"
  } catch {
    $status = $null
    if ($_.Exception.Response) {
      $status = [int]$_.Exception.Response.StatusCode
    }
    if ($status -ne 404) {
      throw
    }
    $body = @{
      tag_name = $Version
      target_commitish = $targetCommit
      name = "DuSheng Panel $Version"
      body = "Agent release assets generated locally from commit $targetCommit."
      draft = $false
      prerelease = $false
    } | ConvertTo-Json
    $release = Invoke-RestMethod -Method Post -Uri "$api/releases" -Headers $headers -ContentType "application/json" -Body $body
    Write-Host "Release created: $($release.html_url)"
  }

  $assets = Invoke-RestMethod -Method Get -Uri $release.assets_url -Headers $headers
  $uploadBase = ($release.upload_url -split "\{")[0]

  foreach ($assetName in $requiredAssets) {
    $file = Get-Item -LiteralPath (Join-Path $releaseDir $assetName)
    $existing = $assets | Where-Object { $_.name -eq $file.Name } | Select-Object -First 1
    if ($existing) {
      Invoke-RestMethod -Method Delete -Uri $existing.url -Headers $headers | Out-Null
      Write-Host "Deleted old asset: $($file.Name)"
    }

    $contentType = if ($file.Name -eq "checksums.txt") { "text/plain" } else { "application/gzip" }
    $assetHeaders = $headers.Clone()
    $assetHeaders["Content-Type"] = $contentType
    $uploadUrl = "${uploadBase}?name=$([System.Uri]::EscapeDataString($file.Name))"
    $uploaded = Invoke-RestMethod -Method Post -Uri $uploadUrl -Headers $assetHeaders -InFile $file.FullName
    Write-Host "Uploaded: $($uploaded.browser_download_url)"
  }

  Write-Host ""
  Write-Host "Published $Version for $Repo"
  Write-Host $release.html_url
} finally {
  Pop-Location
}
