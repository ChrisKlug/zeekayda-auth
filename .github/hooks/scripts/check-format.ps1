# PowerShell equivalent of check-format.sh
$ErrorActionPreference = 'Stop'

$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) { $repoRoot = Get-Location }
Set-Location $repoRoot

# Skip if no .NET projects exist yet
$projects = Get-ChildItem -Recurse -Include *.csproj, *.sln -Exclude .git | Select-Object -First 1
if (-not $projects) { exit 0 }

$output = dotnet format --verify-no-changes 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) { exit 0 }

$reason = "Formatting check failed. Run ``dotnet format`` to fix the issues before finishing.`n`nOutput:`n$output"
if ($reason.Length -gt 4000) { $reason = $reason.Substring(0, 4000) }

@{ decision = "block"; reason = $reason } | ConvertTo-Json -Compress
