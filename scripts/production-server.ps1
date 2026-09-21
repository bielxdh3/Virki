param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('up', 'core-up', 'restart', 'start-tunnel', 'stop', 'status', 'ports', 'revision', 'health', 'logs', 'backup', 'audit-recent', 'audit-cleanup', 'seed-owner', 'sessions-cleanup', 'config')]
  [string] $Action,
  [string] $ExpectedRevision
)

$ErrorActionPreference = 'Stop'
$Root = 'C:\BielOS'
$MarkerPath = Join-Path $Root '.bielos-production-host'
$RevisionPath = Join-Path $Root '.bielos-deploy-revision'
$SourceStatePath = Join-Path $Root '.bielos-source-state'

function Stop-Safely([string] $Message) {
  Write-Error $Message
  exit 1
}

if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
  Stop-Safely 'Canonical BielOS production directory is missing.'
}

Set-Location -LiteralPath $Root
if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) {
  Stop-Safely 'Production-host identity marker is missing.'
}

$marker = @{}
foreach ($line in Get-Content -LiteralPath $MarkerPath) {
  if ($line -match '^([^=]+)=(.*)$') {
    $marker[$matches[1]] = $matches[2]
  }
}

if (
  $marker['role'] -ne 'production' -or
  $marker['protocol'] -ne '1' -or
  $marker['path'] -ne $Root -or
  $marker['hostname'] -ne [Environment]::MachineName
) {
  Stop-Safely 'Production-host identity marker does not match this server.'
}

if (-not (Test-Path -LiteralPath (Join-Path $Root '.env') -PathType Leaf)) {
  Stop-Safely 'Private production environment file is missing.'
}

if (-not (Test-Path -LiteralPath $RevisionPath -PathType Leaf)) {
  Stop-Safely 'Exact deployment revision marker is missing.'
}

$revision = (Get-Content -LiteralPath $RevisionPath -Raw).Trim().ToLowerInvariant()
if ($revision -notmatch '^[0-9a-f]{40}$') {
  Stop-Safely 'Exact deployment revision marker is invalid.'
}

if ($ExpectedRevision) {
  $ExpectedRevision = $ExpectedRevision.ToLowerInvariant()
  if ($ExpectedRevision -notmatch '^[0-9a-f]{40}$' -or $ExpectedRevision -ne $revision) {
    Stop-Safely 'Requested revision does not match the server source.'
  }
}

if (-not (Test-Path -LiteralPath $SourceStatePath -PathType Leaf)) {
  Stop-Safely 'Source-state marker is missing.'
}

$sourceState = @{}
foreach ($line in Get-Content -LiteralPath $SourceStatePath) {
  if ($line -match '^([^=]+)=(.*)$') {
    $sourceState[$matches[1]] = $matches[2]
  }
}
if ($sourceState['branch'] -ne 'main' -or $sourceState['clean'] -ne 'true' -or $sourceState['revision'] -ne $revision) {
  Stop-Safely 'Source-state marker is not a clean exact main revision.'
}

$compose = @(
  'compose',
  '--project-name', 'bielos-prod',
  '--env-file', '.env',
  '-f', 'infra/docker-compose.prod.yml',
  '-f', 'infra/docker-compose.cloudflare.yml'
)
$services = @('public-site', 'hub', 'intake', 'session-cleanup', 'email-worker')

function Invoke-Docker([string[]] $Arguments) {
  & docker @Arguments
  if ($LASTEXITCODE -ne 0) {
    Stop-Safely 'Docker command failed.'
  }
}

function Invoke-DockerCapture([string[]] $Arguments) {
  $output = @(& docker @Arguments 2>&1)
  if ($LASTEXITCODE -ne 0) {
    Stop-Safely 'Docker command failed.'
  }
  return $output
}

function Assert-Revisions {
  foreach ($service in $services) {
    $containers = @(Invoke-DockerCapture ($compose + @('ps', '-q', $service)) | Where-Object { $_.ToString().Trim() })
    if ($containers.Count -ne 1) {
      Stop-Safely "Service $service is not running exactly once."
    }

    $observed = (Invoke-DockerCapture @('inspect', '--format', '{{index .Config.Labels "org.opencontainers.image.revision"}}', $containers[0])).ToString().Trim().ToLowerInvariant()
    if ($observed -ne $revision) {
      Stop-Safely "Service $service revision does not match the accepted source."
    }
  }
  Write-Output "production revision verified: $revision"
}

function Assert-LoopbackPorts {
  foreach ($pair in @(@('public-site', '3000'), @('hub', '3001'))) {
    $binding = (Invoke-DockerCapture ($compose + @('port', $pair[0], $pair[1]))).ToString().Trim()
    if ($binding -notmatch '^127\.0\.0\.1:') {
      Stop-Safely "Service $($pair[0]) is not loopback-bound."
    }
    Write-Output "$($pair[0]) port $binding"
  }
}

function Assert-Health {
  try {
    $public = Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 -Uri 'http://127.0.0.1:3000'
    $hub = Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 -Uri 'http://127.0.0.1:3001/api/health'
    Write-Output "public-site health $([int]$public.StatusCode)"
    Write-Output "hub health $([int]$hub.StatusCode)"
  } catch {
    Stop-Safely 'Remote BielOS health check failed.'
  }
}

switch ($Action) {
  'up' {
    $env:BIELOS_BUILD_REVISION = $revision
    Invoke-Docker ($compose + @('up', '--build', '-d'))
    Assert-Revisions
    Assert-LoopbackPorts
  }
  'core-up' {
    $env:BIELOS_BUILD_REVISION = $revision
    Invoke-Docker ($compose + @('up', '--build', '-d') + $services + @('postgres'))
    Assert-Revisions
    Assert-LoopbackPorts
  }
  'restart' {
    $env:BIELOS_BUILD_REVISION = $revision
    Invoke-Docker ($compose + @('up', '--build', '-d', '--force-recreate'))
    Assert-Revisions
    Assert-LoopbackPorts
  }
  'start-tunnel' {
    Invoke-Docker ($compose + @('up', '-d', 'cloudflared'))
    Write-Output 'cloudflared started'
  }
  'stop' {
    Invoke-Docker ($compose + @('down'))
    Write-Output 'remote BielOS production stopped; persistent volumes preserved'
  }
  'status' {
    Invoke-Docker ($compose + @('ps'))
  }
  'ports' {
    Assert-LoopbackPorts
  }
  'revision' {
    Assert-Revisions
  }
  'health' {
    Assert-Health
  }
  'logs' {
    $rows = @(Invoke-DockerCapture ($compose + @('logs', '--tail=120')))
    Write-Output "remote log lines available: $($rows.Count) (content withheld by production secret policy)"
  }
  'backup' {
    $backupDirectory = Join-Path $Root 'backups'
    New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
    $backupPath = Join-Path $backupDirectory ("bielos-$stamp.dump")
    $command = 'docker compose --project-name bielos-prod --env-file .env -f infra/docker-compose.prod.yml -f infra/docker-compose.cloudflare.yml exec -T postgres sh -c ''pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner --no-privileges'' > "' + $backupPath + '"'
    cmd.exe /d /s /c $command | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backupPath -PathType Leaf) -or (Get-Item -LiteralPath $backupPath).Length -le 0) {
      Stop-Safely 'Remote PostgreSQL backup failed.'
    }
    Write-Output "remote backup created: $([IO.Path]::GetFileName($backupPath))"
  }
  'audit-recent' {
    $rows = @(Invoke-DockerCapture ($compose + @('exec', '-T', 'hub', 'npm', 'run', 'audit:recent', '--workspace', '@bielos/auth')))
    Write-Output "remote audit rows available: $($rows.Count) (content withheld by production secret policy)"
  }
  'audit-cleanup' {
    Invoke-Docker ($compose + @('exec', '-T', 'hub', 'npm', 'run', 'audit:cleanup', '--workspace', '@bielos/auth'))
    Write-Output 'remote audit cleanup completed'
  }
  'seed-owner' {
    Invoke-Docker ($compose + @('exec', '-T', 'hub', 'npm', 'run', 'seed:owner', '--workspace', '@bielos/auth'))
    Write-Output 'remote OWNER seed completed'
  }
  'sessions-cleanup' {
    Invoke-Docker ($compose + @('exec', '-T', 'hub', 'npm', 'run', 'sessions:cleanup', '--workspace', '@bielos/auth'))
    Write-Output 'remote session cleanup completed'
  }
  'config' {
    Invoke-Docker ($compose + @('config', '--no-env-resolution', '--quiet'))
    Write-Output 'remote Compose configuration is valid'
  }
}
