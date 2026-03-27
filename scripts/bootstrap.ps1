param(
  [string]$Repo = "",
  [string]$Ref = "main",
  [string]$Version = "",
  [string]$Profile = "balanced",
  [string]$ArchiveUrl = "",
  [string]$ArchiveFile = "",
  [switch]$KeepWorkdir
)

$ErrorActionPreference = "Stop"

function Fail($Message) {
  throw $Message
}

function Install-Runwall {
  param(
    [string]$Repo = "",
    [string]$Ref = "main",
    [string]$Version = "",
    [string]$Profile = "balanced",
    [string]$ArchiveUrl = "",
    [string]$ArchiveFile = "",
    [switch]$KeepWorkdir
  )

  if ($ArchiveUrl -and $ArchiveFile) {
    Fail "Use only one of -ArchiveUrl or -ArchiveFile."
  }

  if (-not $ArchiveUrl -and -not $ArchiveFile) {
    if (-not $Repo) {
      Fail "-Repo is required unless -ArchiveUrl or -ArchiveFile is used."
    }

    if ($Version) {
      $ArchiveUrl = "https://github.com/$Repo/releases/download/v$Version/runwall-$Version.zip"
    } else {
      $ArchiveUrl = "https://github.com/$Repo/archive/refs/heads/$Ref.zip"
    }
  }

  $TmpBase = Join-Path ([System.IO.Path]::GetTempPath()) ("runwall-bootstrap-" + [System.Guid]::NewGuid().ToString("N"))
  $ExtractDir = Join-Path $TmpBase "extract"
  $ArchivePath = Join-Path $TmpBase "archive.zip"

  New-Item -ItemType Directory -Path $ExtractDir -Force | Out-Null

  try {
    if ($ArchiveFile) {
      Copy-Item -Path $ArchiveFile -Destination $ArchivePath -Force
    } else {
      Invoke-WebRequest -UseBasicParsing -Uri $ArchiveUrl -OutFile $ArchivePath
    }

    Expand-Archive -Path $ArchivePath -DestinationPath $ExtractDir -Force
    $InstallScript = Get-ChildItem -Path $ExtractDir -Recurse -Filter install.ps1 | Select-Object -First 1
    if (-not $InstallScript) {
      Fail "Could not locate extracted install.ps1."
    }

    Write-Host "Installing Runwall with profile $Profile"
    & $InstallScript.FullName -Profile $Profile
    return $LASTEXITCODE
  }
  finally {
    if (-not $KeepWorkdir -and (Test-Path $TmpBase)) {
      Remove-Item -Recurse -Force $TmpBase
    }
  }
}

function Install-SecureClaudeCode {
  param(
    [string]$Repo = "",
    [string]$Ref = "main",
    [string]$Version = "",
    [string]$Profile = "balanced",
    [string]$ArchiveUrl = "",
    [string]$ArchiveFile = "",
    [switch]$KeepWorkdir
  )

  Install-Runwall -Repo $Repo -Ref $Ref -Version $Version -Profile $Profile -ArchiveUrl $ArchiveUrl -ArchiveFile $ArchiveFile -KeepWorkdir:$KeepWorkdir
}

if ($PSCommandPath) {
  exit (Install-Runwall -Repo $Repo -Ref $Ref -Version $Version -Profile $Profile -ArchiveUrl $ArchiveUrl -ArchiveFile $ArchiveFile -KeepWorkdir:$KeepWorkdir)
}
