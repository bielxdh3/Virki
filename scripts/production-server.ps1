param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('start', 'restart', 'prepare', 'start-tunnel', 'stop', 'status', 'ports', 'revision', 'health', 'logs', 'backup-verify', 'migrate', 'migration-status', 'baseline', 'audit-recent', 'audit-cleanup', 'sessions-cleanup', 'config')]
  [string] $Action,
  [Parameter(Mandatory = $true)]
  [string] $Root,
  [string] $ExpectedRevision
)

$ErrorActionPreference = 'Stop'

function Stop-Safely([string] $Message) {
  Write-Error $Message
  exit 1
}

if ($Root -notmatch '^[A-Za-z]:\\[A-Za-z0-9_. -]+(?:\\[A-Za-z0-9_. -]+)*$' -or $Root.Split('\') -contains '..') {
  Stop-Safely 'Production root configuration is invalid.'
}

$MarkerPath = Join-Path $Root '.bielos-production-host'
$RevisionPath = Join-Path $Root '.bielos-deploy-revision'
$SourceStatePath = Join-Path $Root '.bielos-source-state'
$VerificationPath = Join-Path $Root '.bielos-migration-verification'
$BackupDirectory = Join-Path $Root 'backups'
$TransitionMigration = '20260922090000_total_identity_security_rebaseline'
$MigrationSchema = 'packages/database/prisma/schema.prisma'
$MigrationStateQuery = 'SELECT count(*)::text || chr(124) || count(*) FILTER (WHERE "finished_at" IS NULL AND "rolled_back_at" IS NULL)::text || chr(124) || count(*) FILTER (WHERE "rolled_back_at" IS NOT NULL)::text || chr(124) || count(*) FILTER (WHERE "migration_name" = ''' + $TransitionMigration + ''')::text || chr(124) || count(*) FILTER (WHERE "migration_name" = ''0_init'')::text FROM "_prisma_migrations"'
$IdentityBeforeQuery = 'SELECT count(*) FILTER (WHERE "role"::text = ''OWNER'')::text || chr(124) || count(*) FILTER (WHERE "role"::text = ''MEMBER'')::text || chr(124) || count(*) FILTER (WHERE "role"::text = ''ADMIN'')::text || chr(124) || count(*)::text FROM "User"'
$IdentityAfterQuery = 'SELECT count(*) FILTER (WHERE "role"::text = ''ADMIN'')::text || chr(124) || count(*) FILTER (WHERE "role"::text = ''USER'')::text || chr(124) || count(*)::text FROM "User"'

if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
  Stop-Safely 'Configured production directory is missing.'
}
Set-Location -LiteralPath $Root
if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) {
  Stop-Safely 'Production-host identity marker is missing.'
}
$marker = @{}
foreach ($line in Get-Content -LiteralPath $MarkerPath) {
  if ($line -match '^([^=]+)=(.*)$') { $marker[$matches[1]] = $matches[2] }
}
if (
  $marker['role'] -ne 'production' -or
  $marker['protocol'] -ne '1' -or
  $marker['path'] -ne $Root -or
  $marker['hostname'] -ne [Environment]::MachineName
) {
  Stop-Safely 'Production-host identity marker does not match this server.'
}
foreach ($requiredFile in @('.env', '.env.oidc', '.bielos-deploy-revision', '.bielos-source-state')) {
  if (-not (Test-Path -LiteralPath (Join-Path $Root $requiredFile) -PathType Leaf)) {
    Stop-Safely 'Required private configuration or source marker is missing.'
  }
}

$revision = (Get-Content -LiteralPath $RevisionPath -Raw).Trim().ToLowerInvariant()
if ($revision -notmatch '^[0-9a-f]{40}$') { Stop-Safely 'Exact deployment revision marker is invalid.' }
if ($ExpectedRevision) {
  $ExpectedRevision = $ExpectedRevision.ToLowerInvariant()
  if ($ExpectedRevision -notmatch '^[0-9a-f]{40}$' -or $ExpectedRevision -ne $revision) {
    Stop-Safely 'Requested revision does not match the server source.'
  }
}
$sourceState = @{}
foreach ($line in Get-Content -LiteralPath $SourceStatePath) {
  if ($line -match '^([^=]+)=(.*)$') { $sourceState[$matches[1]] = $matches[2] }
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
$services = @('public-site', 'hub', 'oidc-issuer', 'session-cleanup', 'email-worker')
$networkName = 'bielos-prod_default'
$plan = if (Test-Path -LiteralPath (Join-Path $Root "packages\database\prisma\migrations\$TransitionMigration\migration.sql") -PathType Leaf) { 'transition' } elseif (Test-Path -LiteralPath (Join-Path $Root 'packages\database\prisma\migrations\0_init\migration.sql') -PathType Leaf) { 'baseline' } else { Stop-Safely 'Migration plan is missing.' }

function Invoke-Docker([string[]] $Arguments) {
  & docker @Arguments
  if ($LASTEXITCODE -ne 0) { Stop-Safely 'Docker command failed.' }
}

function Invoke-DockerCapture([string[]] $Arguments) {
  $output = @(& docker @Arguments 2>&1)
  if ($LASTEXITCODE -ne 0) { Stop-Safely 'Docker command failed.' }
  return $output
}

function Assert-Revisions {
  foreach ($service in $services) {
    $containers = @(Invoke-DockerCapture ($compose + @('ps', '-q', $service)) | Where-Object { $_.ToString().Trim() })
    if ($containers.Count -ne 1) { Stop-Safely "Service $service is not running exactly once." }
    $inspection = @(Invoke-DockerCapture @('inspect', $containers[0]) | ConvertFrom-Json)
    $observed = ([string]$inspection[0].Config.Labels.'org.opencontainers.image.revision').Trim().ToLowerInvariant()
    if ($observed -ne $revision) { Stop-Safely "Service $service revision does not match the accepted source." }
  }
  Write-Output "production revision verified: $revision"
}

function Assert-LoopbackPorts {
  foreach ($pair in @(@('public-site', '3000'), @('hub', '3001'))) {
    $binding = (Invoke-DockerCapture ($compose + @('port', $pair[0], $pair[1]))).ToString().Trim()
    if ($binding -notmatch '^127\.0\.0\.1:') { Stop-Safely "Service $($pair[0]) is not loopback-bound." }
    Write-Output "$($pair[0]) port is loopback-bound"
  }
}

function Assert-Health {
  try {
    $public = Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 -Uri 'http://127.0.0.1:3000'
    $hub = Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 -Uri 'http://127.0.0.1:3001/api/health'
    $headers = @{ Host = 'portal.biel.dev.br' }
    $discovery = Invoke-RestMethod -TimeoutSec 10 -Uri 'http://127.0.0.1:3001/.well-known/openid-configuration' -Headers $headers
    $adminStatus = 0
    try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 -Uri 'http://127.0.0.1:3001/admin/accounts' -Headers @{ Host = 'hub.biel.dev.br' } | Out-Null }
    catch { $adminStatus = [int]$_.Exception.Response.StatusCode }
    if ([int]$public.StatusCode -ne 200 -or [int]$hub.StatusCode -ne 200 -or $discovery.issuer -ne 'https://portal.biel.dev.br' -or $adminStatus -ne 403) {
      Stop-Safely 'Production boundary or OIDC discovery smoke check failed.'
    }
    Write-Output 'public page, hub health, portal OIDC discovery, and hub Access boundary verified'
  } catch {
    Stop-Safely 'Remote BielOS health check failed.'
  }
}

function Invoke-DatabaseQuery([string] $Query) {
  $encodedQuery = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Query))
  $shell = 'printf %s ' + $encodedQuery + ' | base64 -d | psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At -v ON_ERROR_STOP=1'
  return @(Invoke-DockerCapture ($compose + @('exec', '-T', 'postgres', 'sh', '-lc', $shell)) | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
}

function Read-MigrationState {
  $rows = @(Invoke-DatabaseQuery $MigrationStateQuery)
  if ($rows.Count -ne 1 -or $rows[0] -notmatch '^(\d+)\|(\d+)\|(\d+)\|(\d+)\|(\d+)$') {
    Stop-Safely 'Production migration history could not be verified.'
  }
  return @{ total = [int]$matches[1]; unfinished = [int]$matches[2]; rolledBack = [int]$matches[3]; transition = [int]$matches[4]; baseline = [int]$matches[5] }
}

function Read-CloneQuery([string] $Container, [string] $Query) {
  $rows = @(Invoke-DockerCapture @('exec', $Container, 'psql', '-U', 'bielos_validation', '-d', 'bielos_restore', '-At', '-v', 'ON_ERROR_STOP=1', '-c', $Query) | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
  if ($rows.Count -ne 1) { Stop-Safely 'Restored database verification returned an unexpected result.' }
  return $rows[0]
}

function Assert-IdentityState([string] $Container, [string] $Expected) {
  $query = if ($Expected -eq 'before') { $IdentityBeforeQuery } else { $IdentityAfterQuery }
  $value = Read-CloneQuery $Container $query
  $target = if ($Expected -eq 'before') { '1|1|0|2' } else { '1|1|2' }
  if ($value -ne $target) { Stop-Safely 'Production account-role state does not match the safe migration precondition.' }
}

function Invoke-ClonePrisma([string] $Network, [string] $DatabaseUrl, [string[]] $Tail = @()) {
  $arguments = $compose + @('--profile', 'migration', 'run', '--rm', '--no-deps', '--network', $Network, '--env', "DATABASE_URL=$DatabaseUrl", 'migrate') + $Tail
  Invoke-DockerCapture $arguments | Out-Null
}

function Get-CloneMigrationState([string] $Container) {
  $row = Read-CloneQuery $Container $MigrationStateQuery
  if ($row -notmatch '^(\d+)\|(\d+)\|(\d+)\|(\d+)\|(\d+)$') { Stop-Safely 'Restored database migration state is invalid.' }
  return @{ total = [int]$matches[1]; unfinished = [int]$matches[2]; rolledBack = [int]$matches[3]; transition = [int]$matches[4]; baseline = [int]$matches[5] }
}

function Assert-TransitionHistory($state, [int] $expectedTotal, [int] $baselineCount = 0) {
  if ($state.total -ne $expectedTotal -or $state.unfinished -ne 0 -or $state.rolledBack -ne 0 -or $state.transition -ne 1 -or $state.baseline -ne $baselineCount) {
    Stop-Safely 'Production migration history does not match the expected transition state.'
  }
}

function Assert-CloneMigrationStatus([string] $Network, [string] $DatabaseUrl) {
  Invoke-ClonePrisma $Network $DatabaseUrl @('npx', 'prisma', 'migrate', 'status', '--schema', $MigrationSchema)
}

function New-VerifiedBackup {
  New-Item -ItemType Directory -Force -Path $BackupDirectory | Out-Null
  $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
  $backupPath = Join-Path $BackupDirectory ("bielos-$stamp.dump")
  $containers = @(Invoke-DockerCapture ($compose + @('ps', '-q', 'postgres')) | Where-Object { $_.ToString().Trim() })
  if ($containers.Count -ne 1) { Stop-Safely 'Production database container is not running exactly once.' }
  $containerId = $containers[0].ToString().Trim()
  $containerDumpPath = "/tmp/bielos-$stamp.dump"
  try {
    $dumpCommand = 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner --no-privileges -f ' + $containerDumpPath
    Invoke-DockerCapture @('exec', $containerId, 'sh', '-lc', $dumpCommand) | Out-Null
    Invoke-DockerCapture @('cp', "$containerId`:$containerDumpPath", $backupPath) | Out-Null
    if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf) -or (Get-Item -LiteralPath $backupPath).Length -le 0) {
      Stop-Safely 'Remote PostgreSQL backup failed.'
    }
  } finally {
    & docker exec $containerId rm -f $containerDumpPath *> $null
  }
  return $backupPath
}

function Wait-CloneReady([string] $Container) {
  for ($attempt = 0; $attempt -lt 60; $attempt++) {
    $health = (& docker inspect --format '{{.State.Health.Status}}' $Container 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -eq 0 -and $health -eq 'healthy') { return }
    Start-Sleep -Seconds 1
  }
  Stop-Safely 'Disposable PostgreSQL restore target did not become healthy.'
}

function Validate-BackupAgainstMigrationPlan {
  $backupPath = New-VerifiedBackup
  $backupName = [IO.Path]::GetFileName($backupPath)
  $backupHash = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $containerName = 'bielos-restore-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
  $alias = $containerName
  $password = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
  $databaseUrl = "postgresql://bielos_validation:$password@$alias`:5432/bielos_restore"
  $started = $false
  try {
    Invoke-Docker @('run', '--detach', '--name', $containerName, '--network', $networkName, '--network-alias', $alias, '--env', 'POSTGRES_DB=bielos_restore', '--env', 'POSTGRES_USER=bielos_validation', '--env', "POSTGRES_PASSWORD=$password", '--health-cmd', 'pg_isready -U bielos_validation -d bielos_restore', '--health-interval', '1s', '--health-timeout', '3s', '--health-retries', '60', 'postgres:17-alpine') | Out-Null
    $started = $true
    Wait-CloneReady $containerName
    Invoke-Docker @('cp', $backupPath, "$containerName`:/tmp/bielos-production-backup.dump") | Out-Null
    Invoke-DockerCapture @('exec', '--user', 'postgres', $containerName, 'pg_restore', '--exit-on-error', '--clean', '--if-exists', '--no-owner', '--no-privileges', '-U', 'bielos_validation', '-d', 'bielos_restore', '/tmp/bielos-production-backup.dump') | Out-Null

    if ($plan -eq 'transition') {
      $initial = Get-CloneMigrationState $containerName
      if ($initial.total -ne 14 -or $initial.unfinished -ne 0 -or $initial.rolledBack -ne 0 -or $initial.transition -ne 0 -or $initial.baseline -ne 0) {
        Stop-Safely 'Restored production migration history is not the expected 14 applied migrations.'
      }
      Assert-IdentityState $containerName 'before'
      Invoke-ClonePrisma $networkName $databaseUrl
      $migrated = Get-CloneMigrationState $containerName
      Assert-TransitionHistory $migrated 15
      Assert-IdentityState $containerName 'after'
      Assert-CloneMigrationStatus $networkName $databaseUrl
    } else {
      $initial = Get-CloneMigrationState $containerName
      if ($initial.total -eq 1 -and $initial.unfinished -eq 0 -and $initial.rolledBack -eq 0 -and $initial.transition -eq 0 -and $initial.baseline -eq 1) {
        Assert-IdentityState $containerName 'after'
      } else {
        Assert-TransitionHistory $initial 15
        Assert-IdentityState $containerName 'after'
        Invoke-ClonePrisma $networkName $databaseUrl @('npx', 'prisma', 'migrate', 'resolve', '--applied', '0_init', '--schema', $MigrationSchema)
        $resolved = Get-CloneMigrationState $containerName
        Assert-TransitionHistory $resolved 16 1
        $deleteSql = 'DO $$ BEGIN IF (SELECT count(*) FROM "_prisma_migrations") <> 16 OR (SELECT count(*) FROM "_prisma_migrations" WHERE "migration_name" = ''0_init'') <> 1 OR (SELECT count(*) FROM "_prisma_migrations" WHERE "migration_name" = ''' + $TransitionMigration + ''') <> 1 OR EXISTS (SELECT 1 FROM "_prisma_migrations" WHERE "finished_at" IS NULL OR "rolled_back_at" IS NOT NULL) THEN RAISE EXCEPTION ''Unexpected history during verified baseline convergence''; END IF; DELETE FROM "_prisma_migrations" WHERE "migration_name" <> ''0_init''; END $$'
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($deleteSql))
        $shell = 'printf %s ' + $encoded + ' | base64 -d | psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1'
        Invoke-DockerCapture @('exec', $containerName, 'sh', '-lc', $shell) | Out-Null
        $final = Get-CloneMigrationState $containerName
        if ($final.total -ne 1 -or $final.unfinished -ne 0 -or $final.rolledBack -ne 0 -or $final.transition -ne 0 -or $final.baseline -ne 1) {
          Stop-Safely 'Restored database baseline state is invalid.'
        }
      }
      Assert-CloneMigrationStatus $networkName $databaseUrl
    }
  } finally {
    if ($started) { & docker rm --force --volumes $containerName *> $null }
  }

  $verifiedAt = (Get-Date).ToUniversalTime().ToString('o')
  Set-Content -LiteralPath $VerificationPath -Encoding ascii -Value @(
    "revision=$revision",
    "mode=$plan",
    "backup_name=$backupName",
    "backup_sha256=$backupHash",
    "verified_at=$verifiedAt"
  )
  Write-Output 'production backup restored and migration plan verified in an isolated PostgreSQL container'
}

function Assert-BackupVerification([string] $expectedPlan) {
  if (-not (Test-Path -LiteralPath $VerificationPath -PathType Leaf)) { Stop-Safely 'Verified backup marker is missing.' }
  $values = @{}
  foreach ($line in Get-Content -LiteralPath $VerificationPath) {
    if ($line -match '^([^=]+)=(.*)$') { $values[$matches[1]] = $matches[2] }
  }
  if ($values['revision'] -ne $revision -or $values['mode'] -ne $expectedPlan -or $values['backup_name'] -notmatch '^bielos-\d{8}-\d{6}\.dump$' -or $values['backup_sha256'] -notmatch '^[0-9a-f]{64}$') {
    Stop-Safely 'Verified backup marker does not match this source and migration plan.'
  }
  try { $verifiedAt = [DateTime]::Parse($values['verified_at']).ToUniversalTime() }
  catch { Stop-Safely 'Verified backup timestamp is invalid.' }
  if (([DateTime]::UtcNow - $verifiedAt).TotalHours -gt 24 -or $verifiedAt -gt [DateTime]::UtcNow.AddMinutes(5)) {
    Stop-Safely 'Verified backup is stale.'
  }
  $backupPath = Join-Path $BackupDirectory $values['backup_name']
  if (-not (Test-Path -LiteralPath $backupPath -PathType Leaf)) { Stop-Safely 'Verified backup file is missing.' }
  $actualHash = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualHash -ne $values['backup_sha256']) { Stop-Safely 'Verified backup file changed after restore verification.' }
}

function Assert-TransitionDatabaseReady {
  $state = Read-MigrationState
  if ($state.total -eq 15 -and $state.unfinished -eq 0 -and $state.rolledBack -eq 0 -and $state.transition -eq 1 -and $state.baseline -eq 0) { return $state }
  if ($state.total -eq 14 -and $state.unfinished -eq 0 -and $state.rolledBack -eq 0 -and $state.transition -eq 0 -and $state.baseline -eq 0) { return $state }
  Stop-Safely 'Production migration history does not match the verified transition precondition.'
}

function Stop-OldWriters {
  $legacyIds = @(Invoke-DockerCapture @('ps', '--quiet', '--filter', 'label=com.docker.compose.project=bielos-prod', '--filter', 'label=com.docker.compose.service=intake') | Where-Object { $_.ToString().Trim() })
  if ($legacyIds.Count -gt 1) { Stop-Safely 'More than one legacy intake container is present.' }
  foreach ($containerId in $legacyIds) {
    $inspection = @(Invoke-DockerCapture @('inspect', $containerId) | ConvertFrom-Json)
    $labels = $inspection[0].Config.Labels
    if ($labels.'com.docker.compose.project' -ne 'bielos-prod' -or $labels.'com.docker.compose.service' -ne 'intake') {
      Stop-Safely 'Legacy service ownership could not be verified.'
    }
    Invoke-DockerCapture @('stop', $containerId) | Out-Null
  }
  Invoke-DockerCapture ($compose + @('stop', 'public-site', 'hub', 'oidc-issuer', 'session-cleanup', 'email-worker')) | Out-Null
}

function Remove-OldIntakeContainer {
  $legacyIds = @(Invoke-DockerCapture @('ps', '--all', '--quiet', '--filter', 'label=com.docker.compose.project=bielos-prod', '--filter', 'label=com.docker.compose.service=intake') | Where-Object { $_.ToString().Trim() })
  if ($legacyIds.Count -gt 1) { Stop-Safely 'More than one legacy intake container is present.' }
  foreach ($containerId in $legacyIds) {
    $inspection = @(Invoke-DockerCapture @('inspect', $containerId) | ConvertFrom-Json)
    $labels = $inspection[0].Config.Labels
    if ($labels.'com.docker.compose.project' -ne 'bielos-prod' -or $labels.'com.docker.compose.service' -ne 'intake') {
      Stop-Safely 'Legacy service ownership could not be verified.'
    }
    Invoke-DockerCapture @('rm', '--force', $containerId) | Out-Null
  }
}

function Invoke-ProductionBaseline {
  $state = Read-MigrationState
  if ($state.total -eq 1 -and $state.unfinished -eq 0 -and $state.rolledBack -eq 0 -and $state.transition -eq 0 -and $state.baseline -eq 1) { return }
  if ($state.total -eq 15 -and $state.unfinished -eq 0 -and $state.rolledBack -eq 0 -and $state.transition -eq 1 -and $state.baseline -eq 0) {
    Invoke-DockerCapture ($compose + @('--profile', 'migration', 'run', '--rm', '--no-deps', 'migrate', 'npx', 'prisma', 'migrate', 'resolve', '--applied', '0_init', '--schema', $MigrationSchema)) | Out-Null
    $state = Read-MigrationState
  }
  if ($state.total -ne 16 -or $state.unfinished -ne 0 -or $state.rolledBack -ne 0 -or $state.transition -ne 1 -or $state.baseline -ne 1) {
    Stop-Safely 'Production history cannot be safely reconciled to the clean baseline.'
  }
  $deleteSql = 'DO $$ BEGIN IF (SELECT count(*) FROM "_prisma_migrations") <> 16 OR (SELECT count(*) FROM "_prisma_migrations" WHERE "migration_name" = ''0_init'') <> 1 OR (SELECT count(*) FROM "_prisma_migrations" WHERE "migration_name" = ''' + $TransitionMigration + ''') <> 1 OR EXISTS (SELECT 1 FROM "_prisma_migrations" WHERE "finished_at" IS NULL OR "rolled_back_at" IS NOT NULL) THEN RAISE EXCEPTION ''Unexpected history during verified baseline convergence''; END IF; DELETE FROM "_prisma_migrations" WHERE "migration_name" <> ''0_init''; END $$'
  Invoke-DatabaseQuery $deleteSql | Out-Null
  $finalState = Read-MigrationState
  if ($finalState.total -ne 1 -or $finalState.unfinished -ne 0 -or $finalState.rolledBack -ne 0 -or $finalState.transition -ne 0 -or $finalState.baseline -ne 1) {
    Stop-Safely 'Production migration history did not converge to the clean baseline.'
  }
  Invoke-DockerCapture ($compose + @('--profile', 'migration', 'run', '--rm', '--no-deps', 'migrate', 'npx', 'prisma', 'migrate', 'status', '--schema', $MigrationSchema)) | Out-Null
}

function Assert-RoleCounts {
  $result = @(Invoke-DatabaseQuery $IdentityAfterQuery)
  if ($result.Count -ne 1 -or $result[0] -ne '1|1|2') { Stop-Safely 'Production account-role state did not converge safely.' }
}

function Assert-ProductionMigrationReady {
  $state = Read-MigrationState
  if ($plan -eq 'transition') { Assert-TransitionHistory $state 15 }
  elseif ($state.total -ne 1 -or $state.unfinished -ne 0 -or $state.rolledBack -ne 0 -or $state.transition -ne 0 -or $state.baseline -ne 1) {
    Stop-Safely 'Production migration status is not the clean baseline.'
  }
  Assert-RoleCounts
  Invoke-DockerCapture ($compose + @('--profile', 'migration', 'run', '--rm', '--no-deps', 'migrate', 'npx', 'prisma', 'migrate', 'status', '--schema', $MigrationSchema)) | Out-Null
}

switch ($Action) {
  'prepare' {
    if (-not (Test-Path -LiteralPath (Join-Path $Root '.env.oidc') -PathType Leaf)) { Stop-Safely 'OIDC private environment is missing.' }
    $env:BIELOS_BUILD_REVISION = $revision
    Invoke-Docker ($compose + @('--profile', 'migration', 'build'))
    Write-Output 'production images built from the accepted source'
  }
  'backup-verify' {
    if (-not (Test-Path -LiteralPath (Join-Path $Root '.env.oidc') -PathType Leaf)) { Stop-Safely 'OIDC private environment is missing.' }
    Validate-BackupAgainstMigrationPlan
  }
  'migrate' {
    if ($plan -ne 'transition') { Stop-Safely 'Transition migration action does not match the source.' }
    Assert-BackupVerification 'transition'
    $state = Assert-TransitionDatabaseReady
    if ($state.total -eq 14) {
      Stop-OldWriters
      Invoke-DockerCapture ($compose + @('--profile', 'migration', 'run', '--rm', '--no-deps', 'migrate')) | Out-Null
      Remove-OldIntakeContainer
    }
    $finalState = Read-MigrationState
    if ($finalState.total -ne 15 -or $finalState.unfinished -ne 0 -or $finalState.rolledBack -ne 0 -or $finalState.transition -ne 1 -or $finalState.baseline -ne 0) {
      Stop-Safely 'Production transition migration did not finish cleanly.'
    }
    Assert-RoleCounts
    Invoke-DockerCapture ($compose + @('--profile', 'migration', 'run', '--rm', '--no-deps', 'migrate', 'npx', 'prisma', 'migrate', 'status', '--schema', $MigrationSchema)) | Out-Null
    Write-Output 'production transition migration completed after verified restore test'
  }
  'baseline' {
    if ($plan -ne 'baseline') { Stop-Safely 'Baseline action does not match the source.' }
    Assert-BackupVerification 'baseline'
    Assert-RoleCounts
    Stop-OldWriters
    Invoke-ProductionBaseline
    Remove-OldIntakeContainer
    Write-Output 'production migration history reconciled to the clean baseline'
  }
  'migration-status' {
    $state = Read-MigrationState
    if ($plan -eq 'transition') { Assert-TransitionHistory $state 15 }
    else {
      if ($state.total -ne 1 -or $state.unfinished -ne 0 -or $state.rolledBack -ne 0 -or $state.transition -ne 0 -or $state.baseline -ne 1) { Stop-Safely 'Production migration status is not the clean baseline.' }
    }
    Invoke-DockerCapture ($compose + @('--profile', 'migration', 'run', '--rm', '--no-deps', 'migrate', 'npx', 'prisma', 'migrate', 'status', '--schema', $MigrationSchema)) | Out-Null
    Write-Output "production migration status verified: $($state.total) applied record(s)"
  }
  'start' {
    Assert-ProductionMigrationReady
    $env:BIELOS_BUILD_REVISION = $revision
    Remove-OldIntakeContainer
    Invoke-Docker ($compose + @('up', '-d'))
    Assert-Revisions
    Assert-LoopbackPorts
  }
  'restart' {
    Assert-ProductionMigrationReady
    $env:BIELOS_BUILD_REVISION = $revision
    Remove-OldIntakeContainer
    Invoke-Docker ($compose + @('up', '-d', '--force-recreate'))
    Assert-Revisions
    Assert-LoopbackPorts
    Assert-Health
    Remove-Item -LiteralPath $VerificationPath -Force -ErrorAction SilentlyContinue
  }
  'start-tunnel' {
    Invoke-Docker ($compose + @('up', '-d', 'cloudflared'))
    Write-Output 'cloudflared started'
  }
  'stop' {
    Invoke-Docker ($compose + @('stop'))
    Write-Output 'remote BielOS services stopped; persistent data preserved'
  }
  'status' { Invoke-Docker ($compose + @('ps')) }
  'ports' { Assert-LoopbackPorts }
  'revision' { Assert-Revisions }
  'health' { Assert-Health }
  'logs' {
    $rows = @(Invoke-DockerCapture ($compose + @('logs', '--tail=120')))
    Write-Output "remote log lines available: $($rows.Count) (content withheld)"
  }
  'audit-recent' {
    $rows = @(Invoke-DockerCapture ($compose + @('exec', '-T', 'hub', 'npm', 'run', 'audit:recent', '--workspace', '@bielos/auth')))
    Write-Output "remote audit rows available: $($rows.Count) (content withheld)"
  }
  'audit-cleanup' {
    Invoke-DockerCapture ($compose + @('exec', '-T', 'hub', 'npm', 'run', 'audit:cleanup', '--workspace', '@bielos/auth')) | Out-Null
    Write-Output 'remote audit cleanup completed'
  }
  'sessions-cleanup' {
    Invoke-DockerCapture ($compose + @('exec', '-T', 'hub', 'npm', 'run', 'sessions:cleanup', '--workspace', '@bielos/auth')) | Out-Null
    Write-Output 'remote session cleanup completed'
  }
  'config' {
    Invoke-DockerCapture ($compose + @('config', '--no-env-resolution', '--quiet')) | Out-Null
    Write-Output 'remote Compose configuration is valid'
  }
}
