param(
  [string]$Profile = ""
)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptPath = Join-Path $Root "update.sh"

if (Get-Command bash -ErrorAction SilentlyContinue) {
  if ($Profile -eq "") {
    & bash $ScriptPath
  } else {
    & bash $ScriptPath $Profile
  }
  exit $LASTEXITCODE
}

Write-Error "bash was not found. On Windows, run this from Git Bash or WSL, or install bash and retry."
exit 1

