# Stop GraphGuard AI local services without deleting graph data.
$ErrorActionPreference = "Stop"
docker stop graphguard-local 2>$null | Out-Null
Get-Process -Name python,pythonw -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith((Join-Path $PSScriptRoot ".venv"), [System.StringComparison]::OrdinalIgnoreCase) } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "GraphGuard AI local services stopped. Persistent data remains in .local-data."
