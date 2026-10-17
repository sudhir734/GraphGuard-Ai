# GraphGuard AI local launcher for Windows PowerShell.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Install Docker Desktop and retry." }
docker info *> $null
if ($LASTEXITCODE -ne 0) { throw "Docker Desktop is not running. Start it and retry." }
$dataPath = Join-Path $PSScriptRoot ".local-data"
$envPath = Join-Path $PSScriptRoot ".local.env"
New-Item -ItemType Directory -Force -Path $dataPath | Out-Null
if (-not (Test-Path $envPath)) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $password = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','A').Replace('/','B')
    [System.IO.File]::WriteAllText($envPath, "FALKORDB_PASSWORD=$password" + [Environment]::NewLine)
    $password = $null
    $bytes = $null
}
$line = Get-Content $envPath | Where-Object { $_ -match '^FALKORDB_PASSWORD=' } | Select-Object -First 1
if (-not $line) { throw ".local.env is missing FALKORDB_PASSWORD. Remove it and rerun to generate a new local secret." }
$dbPassword = $line.Substring("FALKORDB_PASSWORD=".Length)
if ([string]::IsNullOrWhiteSpace($dbPassword)) { throw "Local database password is empty." }
$image = "graphguard-ai-local:dev"
Write-Host "Building GraphGuard AI local API + FalkorDB image..."
docker build -f Dockerfile.blitz -t $image .
if ($LASTEXITCODE -ne 0) { throw "Docker image build failed." }
$existing = docker ps -a --filter "name=^graphguard-local$" --format "{{.Names}}"
if ($existing -eq "graphguard-local") { docker rm -f graphguard-local | Out-Null }
Write-Host "Starting local FalkorDB + API. Graph data folder: $dataPath"
$dockerArgs = @("run","-d","--name","graphguard-local","--restart","unless-stopped","-p","127.0.0.1:8000:8000","--mount","type=bind,source=$dataPath,target=/var/lib/falkordb/data","--env","FALKORDB_PASSWORD=$dbPassword","--env","FALKORDB_GRAPH=GraphGuardDemo","--env","FALKORDB_HOST=127.0.0.1","--env","FALKORDB_PORT=6379","--env","FALKORDB_TLS=false","--env","GRAPHGUARD_ENABLE_DISCOVERY=true","--env","GRAPHGUARD_ALLOW_LIVE_ENRICHMENT=true","--env","GRAPHGUARD_ENABLE_AUDIT_API=true",$image)
docker @dockerArgs | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Failed to start GraphGuard local container." }
Write-Host "Waiting for API and graph readiness..."
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health/ready" -TimeoutSec 2
        if ($health.falkordb.status -eq "ok") { $ready = $true; break }
    } catch { Start-Sleep -Seconds 2 }
}
if (-not $ready) { docker logs --tail 80 graphguard-local; throw "GraphGuard did not become ready. See logs above." }
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Creating Python environment for the UI..."
    py -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Install Python 3.10+ and retry." }
}
Write-Host "Installing/verifying Python UI dependencies..."
& ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Python dependency installation failed." }
$startArgs = @{ FilePath=(Join-Path $PSScriptRoot ".venv\Scripts\python.exe"); ArgumentList=@("-m","streamlit","run","app.py","--server.address","127.0.0.1","--server.port","8501","--browser.gatherUsageStats","false"); WorkingDirectory=$PSScriptRoot; Environment=@{ GRAPHGUARD_API_URL="http://127.0.0.1:8000"; GRAPHGUARD_PUBLIC_DEMO="true" } }
Start-Process @startArgs
Start-Sleep -Seconds 3
Start-Process "http://127.0.0.1:8501"
Write-Host "GraphGuard AI is running locally:"
Write-Host "UI:       http://127.0.0.1:8501"
Write-Host "API:      http://127.0.0.1:8000"
Write-Host "API docs: http://127.0.0.1:8000/docs"
Write-Host "Stop with .\stop-local.ps1"
Write-Host "Persistent graph data: .local-data (keep this folder). Local secret: .local.env (do not share it)."
