param(
  [string]$Version = "dev",
  [string]$OutputDir = "release",
  [ValidateSet("ndpi", "heuristic")]
  [string]$DPIEngine = "ndpi",
  [switch]$Clean
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$outputPath = Join-Path $repoRoot $OutputDir

if ($Clean -and (Test-Path -LiteralPath $outputPath)) {
  Remove-Item -LiteralPath $outputPath -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

if ($DPIEngine -eq "ndpi" -and -not (Get-Command docker -ErrorAction SilentlyContinue)) {
  throw "Docker with buildx is required to build the real nDPI sidecar. Install Docker, or explicitly use -DPIEngine heuristic for a fallback-only release."
}

$targets = @(
  @{ OS = "linux"; Arch = "amd64" },
  @{ OS = "linux"; Arch = "arm64" }
)

$artifacts = @()

foreach ($target in $targets) {
  $os = $target.OS
  $arch = $target.Arch
  $workDir = Join-Path $outputPath "dusheng-agent-$os-$arch"
  $binaryPath = Join-Path $workDir "dusheng-agent"
  $dpiBinaryPath = Join-Path $workDir "dusheng-dpi"
  $archiveName = "dusheng-agent-$os-$arch.tar.gz"
  $archivePath = Join-Path $outputPath $archiveName

  if (Test-Path -LiteralPath $workDir) {
    Remove-Item -LiteralPath $workDir -Recurse -Force
  }
  New-Item -ItemType Directory -Force -Path $workDir | Out-Null

  Write-Host "Building $archiveName"
  $env:GOOS = $os
  $env:GOARCH = $arch
  $env:CGO_ENABLED = "0"
  go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $binaryPath ./apps/agent/cmd/agent
  if ($DPIEngine -eq "ndpi") {
    docker buildx build --platform "$os/$arch" --build-arg "VERSION=$Version" --output "type=local,dest=$workDir" -f deploy/dpi-release.Dockerfile .
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $dpiBinaryPath)) {
      throw "Failed to build real nDPI sidecar for $os/$arch"
    }
  } else {
    Write-Warning "Building heuristic-only DPI sidecar for $os/$arch"
    go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $dpiBinaryPath ./apps/dpi/cmd/dpi
  }

  if (Test-Path -LiteralPath $archivePath) {
    Remove-Item -LiteralPath $archivePath -Force
  }

  Push-Location $workDir
  try {
    $archiveEntries = @("dusheng-agent", "dusheng-dpi")
    if (Test-Path -LiteralPath (Join-Path $workDir "dusheng-dpi-lib")) {
      $archiveEntries += "dusheng-dpi-lib"
    }
    if (Test-Path -LiteralPath (Join-Path $workDir "THIRD_PARTY_NOTICES.md")) {
      $archiveEntries += "THIRD_PARTY_NOTICES.md"
    }
    tar -czf $archivePath @archiveEntries
  } finally {
    Pop-Location
  }

  $artifacts += Get-Item -LiteralPath $archivePath
}

$checksumPath = Join-Path $outputPath "checksums.txt"
if (Test-Path -LiteralPath $checksumPath) {
  Remove-Item -LiteralPath $checksumPath -Force
}

foreach ($artifact in $artifacts) {
  $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $artifact.FullName
  "$($hash.Hash.ToLowerInvariant())  $($artifact.Name)" | Add-Content -LiteralPath $checksumPath -Encoding ASCII
}

Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Agent release artifacts generated in $outputPath"
Get-ChildItem -LiteralPath $outputPath -File | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize
