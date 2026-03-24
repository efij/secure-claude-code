$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptPath = Join-Path $Root "uninstall.sh"

if (Get-Command bash -ErrorAction SilentlyContinue) {
  & bash $ScriptPath
  exit $LASTEXITCODE
}

Write-Error "bash was not found. On Windows, run this from Git Bash or WSL, or install bash and retry."
exit 1

