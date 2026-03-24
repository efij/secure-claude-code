param(
  [string]$Profile = "balanced"
)

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptPath = Join-Path $Root "install.sh"

if (Get-Command bash -ErrorAction SilentlyContinue) {
  & bash $ScriptPath $Profile
  exit $LASTEXITCODE
}

Write-Error "bash was not found. On Windows, run this from Git Bash or WSL, or install bash and retry."
exit 1

