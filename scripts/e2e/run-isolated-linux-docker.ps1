param(
  [switch]$E2EOnly,
  [switch]$IntegrationOnly,
  [switch]$UnitOnly,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$PlaywrightArguments = @()
)

$ErrorActionPreference = 'Stop'
$playwrightArgumentsJson = $env:VIRKI_E2E_PLAYWRIGHT_ARGUMENTS_JSON
if ($playwrightArgumentsJson) {
  try {
    $decodedPlaywrightArguments = ConvertFrom-Json -InputObject $playwrightArgumentsJson -ErrorAction Stop
  } catch {
    throw 'Playwright arguments must be a JSON array of strings.'
  }
  if ($decodedPlaywrightArguments -isnot [System.Array] -or @($decodedPlaywrightArguments | Where-Object { $_ -isnot [string] }).Count -gt 0) {
    throw 'Playwright arguments must be a JSON array of strings.'
  }
  $PlaywrightArguments = [string[]]$decodedPlaywrightArguments
}
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$runId = [Guid]::NewGuid().ToString('N').Substring(0, 10)
$tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$snapshotDirectory = Join-Path $tempRoot ('virki-e2e-' + $runId)
$bundlePath = Join-Path $snapshotDirectory 'repository.bundle'
$stagedPatchPath = Join-Path $snapshotDirectory 'staged.patch'
$workingPatchPath = Join-Path $snapshotDirectory 'working-tree.patch'
$networkName = 'virki-e2e-' + $runId
$databaseName = 'virki-e2e-postgres-' + $runId
$runnerName = 'virki-e2e-runner-' + $runId
$passwords = @{
  bootstrap = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
  runtime = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
  migrator = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
  audit = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
  test = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
}
$databaseUrl = {
  param([string]$User, [string]$Password, [string]$DatabaseHost)
  $builder = [System.UriBuilder]::new('postgresql', $DatabaseHost, 5432, '/virki_e2e_test')
  $builder.UserName = $User
  $builder.Password = $Password
  $builder.Query = 'schema=public'
  $builder.Uri.AbsoluteUri
}
$urls = @{
  e2e = & $databaseUrl 'virki_runtime_test' $passwords.test 'postgres'
  runtime = & $databaseUrl 'virki_runtime' $passwords.runtime 'postgres'
  migrator = & $databaseUrl 'virki_migrator' $passwords.migrator 'postgres'
  audit = & $databaseUrl 'virki_audit_maintenance' $passwords.audit 'postgres'
  integration = & $databaseUrl 'virki_runtime_test' $passwords.test '127.0.0.1'
}
$script:results = [System.Collections.Generic.List[string]]::new()
$script:runnerName = $runnerName

$selectedStageCount = 0
if ($E2EOnly) { $selectedStageCount++ }
if ($IntegrationOnly) { $selectedStageCount++ }
if ($UnitOnly) { $selectedStageCount++ }
if ($selectedStageCount -gt 1) { throw 'Choose only one isolated runner stage.' }

function Invoke-Stage {
  param([string]$Name, [string[]]$Command, [string[]]$Environment = @())
  Write-Output "`n[$Name]"
  & docker exec --workdir /workspace @Environment $script:runnerName @Command
  $exitCode = $LASTEXITCODE
  $script:results.Add($Name + '=' + $exitCode)
  Write-Output "[RESULT] $Name exit=$exitCode"
}

function Invoke-LoggedStage {
  param([string]$Name, [string]$LogName, [string]$CommandText, [string[]]$Environment = @())
  $shellCommand = $CommandText + ' > /tmp/' + $LogName + '.log 2>&1; status=$?; tail -n 80 /tmp/' + $LogName + '.log; exit $status'
  Invoke-Stage $Name @('bash', '-lc', $shellCommand) $Environment
}

try {
  New-Item -ItemType Directory -Path $snapshotDirectory -ErrorAction Stop | Out-Null
  & git bundle create $bundlePath --all
  if ($LASTEXITCODE -ne 0) { throw 'Could not create a temporary Git bundle.' }
  & git diff --cached --binary ("--output=" + $stagedPatchPath)
  if ($LASTEXITCODE -ne 0) { throw 'Could not snapshot staged worktree changes.' }
  & git diff --binary ("--output=" + $workingPatchPath)
  if ($LASTEXITCODE -ne 0) { throw 'Could not snapshot unstaged worktree changes.' }
  $untrackedFiles = @(& git ls-files --others --exclude-standard)
  if ($LASTEXITCODE -ne 0) { throw 'Could not inventory nonignored untracked files.' }
  $allowedUntracked = @('apps/hub/src/app/recover/recovery-completion-form.tsx', 'e2e/recovery-invitation.spec.mts', 'scripts/e2e/run-isolated-linux-docker.ps1', 'scripts/e2e/run-e2e.mjs', 'scripts/e2e/run-e2e.test.mjs')
  if ($untrackedFiles | Where-Object { $_ -notin $allowedUntracked }) {
    throw 'The Docker E2E snapshot found an unexpected untracked file; review it before copying.'
  }

  & docker network create --driver bridge --internal $networkName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not create the private Docker network.' }
  & docker create --name $databaseName --network $networkName --network-alias postgres `
    --tmpfs '/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m' `
    --health-cmd 'pg_isready -h 127.0.0.1 -U virki_bootstrap -d virki_e2e_test' `
    --health-interval 1s --health-timeout 3s --health-retries 90 `
    --env 'POSTGRES_DB=virki_e2e_test' --env 'POSTGRES_USER=virki_bootstrap' `
    --env "POSTGRES_PASSWORD=$($passwords.bootstrap)" `
    --env "VIRKI_RUNTIME_DB_PASSWORD=$($passwords.runtime)" `
    --env "VIRKI_MIGRATOR_DB_PASSWORD=$($passwords.migrator)" `
    --env "VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD=$($passwords.audit)" `
    --env "VIRKI_E2E_DATABASE_PASSWORD=$($passwords.test)" `
    'postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not create the disposable PostgreSQL container.' }

  & docker cp (Join-Path $repoRoot 'infra/postgres-init/10-virki-database-roles.sh') ($databaseName + ':/docker-entrypoint-initdb.d/10-virki-database-roles.sh') | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the database role initializer.' }
  & docker cp (Join-Path $repoRoot 'scripts/e2e/20-virki-e2e-runtime-test-role.sh') ($databaseName + ':/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh') | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the E2E role initializer.' }
  & docker start $databaseName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the disposable PostgreSQL container.' }

  $databaseReady = $false
  for ($attempt = 0; $attempt -lt 90; $attempt++) {
    $health = (& docker inspect --format '{{.State.Health.Status}}' $databaseName 2>$null).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the disposable PostgreSQL health state.' }
    if ($health -eq 'healthy') { $databaseReady = $true; break }
    if ($health -eq 'unhealthy') { break }
    Start-Sleep -Seconds 1
  }
  if (-not $databaseReady) {
    & docker logs $databaseName
    throw 'Disposable PostgreSQL did not become healthy within 90 seconds.'
  }

  & docker create --name $runnerName --network bridge --entrypoint /bin/bash 'node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8' -lc 'sleep infinity' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not create the isolated Playwright runner.' }
  & docker cp $bundlePath ($runnerName + ':/tmp/virki.bundle')
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the temporary Git bundle.' }
  & docker cp $stagedPatchPath ($runnerName + ':/tmp/staged.patch')
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the staged worktree patch.' }
  & docker cp $workingPatchPath ($runnerName + ':/tmp/working-tree.patch')
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the unstaged worktree patch.' }
  & docker start $runnerName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the isolated Playwright runner.' }
  & docker network connect $networkName $runnerName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not connect the runner to the private database network.' }

  & docker exec $runnerName bash -lc 'apt-get update -qq && apt-get install -y --no-install-recommends git libnss3-tools'
  if ($LASTEXITCODE -ne 0) { throw 'Could not install Linux Git and Chromium NSS tooling.' }
  $nodeVersion = (& docker exec $runnerName node --version).Trim()
  $npmVersion = (& docker exec $runnerName npm --version).Trim()
  Write-Output "Linux runtime: Node $nodeVersion, npm $npmVersion"
  if ($nodeVersion -notmatch '^v22\.' -or [version]$npmVersion -lt [version]'10.9.3' -or [version]$npmVersion -ge [version]'11.0.0') {
    throw 'The Linux runner does not satisfy the repository Node/npm engines.'
  }
  & docker exec $runnerName bash -lc 'git clone --branch cdx/virki-open-issues /tmp/virki.bundle /workspace'
  if ($LASTEXITCODE -ne 0) { throw 'Could not clone the temporary Git snapshot.' }
  & docker exec --workdir /workspace $runnerName bash -lc 'if [ -s /tmp/staged.patch ]; then git apply --binary /tmp/staged.patch; fi; if [ -s /tmp/working-tree.patch ]; then git apply --binary /tmp/working-tree.patch; fi'
  if ($LASTEXITCODE -ne 0) { throw 'Could not apply the current worktree changes to the temporary clone.' }
  foreach ($relativePath in $untrackedFiles) {
    & docker cp (Join-Path $repoRoot $relativePath) ($runnerName + ':/workspace/' + $relativePath.Replace('\', '/')) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not copy an untracked test file into the temporary clone.' }
  }

  & docker exec $runnerName bash -lc 'mkdir -p /workspace/packages/database/generated /workspace/prisma/generated /workspace/apps/hub/.next /workspace/apps/public-site/.next /workspace/apps/issuer/.next /workspace/test-results /workspace/playwright-report'
  if ($LASTEXITCODE -ne 0) { throw 'Could not prepare isolated workspace output directories.' }
  & docker exec --workdir /workspace $runnerName npm ci
  if ($LASTEXITCODE -ne 0) { throw 'Locked Linux dependency installation failed.' }
  Invoke-Stage 'tooling-policy-dependencies' @('bash', '-lc', 'npm ls @prisma/config deepmerge-ts --all')
  Invoke-LoggedStage 'tooling-policy-tests' 'tooling-policy' 'node scripts/tooling-audit-policy.mjs && node --test scripts/tooling-audit-policy.test.mjs'
  if (-not $IntegrationOnly -and -not $UnitOnly) {
    & docker exec --workdir /workspace $runnerName npx playwright install --with-deps chromium
    if ($LASTEXITCODE -ne 0) { throw 'The locked Playwright Chromium and Linux dependencies did not install.' }
  }

  & docker network disconnect bridge $runnerName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not disconnect the runner egress network.' }
  & docker exec --workdir /workspace --env ("DATABASE_URL=" + $urls.runtime) --env ("MIGRATION_DATABASE_URL=" + $urls.migrator) $runnerName npm run prisma:migrate:deploy
  if ($LASTEXITCODE -ne 0) { throw 'Committed migrations did not apply to the disposable database.' }
  $auditCleanupGrantPath = Join-Path $snapshotDirectory 'audit-cleanup-grant.sql'
  [System.IO.File]::WriteAllText($auditCleanupGrantPath, 'GRANT SELECT ("actorUserId") ON TABLE public."AuditLog" TO virki_audit_maintenance;', [System.Text.Encoding]::ASCII)
  & docker cp $auditCleanupGrantPath ($databaseName + ':/tmp/audit-cleanup-grant.sql') | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the fixture-scoped audit cleanup grant.' }
  & docker exec $databaseName psql --username virki_bootstrap --dbname virki_e2e_test --set ON_ERROR_STOP=1 --file /tmp/audit-cleanup-grant.sql | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not grant fixture-scoped audit cleanup access.' }
  & docker exec --detach $runnerName node -e "const net=require('node:net');net.createServer(s=>{const d=net.connect(5432,'postgres');s.pipe(d);d.pipe(s)}).listen(5432,'127.0.0.1')"
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the loopback-only integration database proxy.' }

  if (-not $E2EOnly -and -not $IntegrationOnly -and -not $UnitOnly) {
    Invoke-Stage 'runtime' @('bash', '-lc', 'node --version && npm --version && uname -s')
    Invoke-LoggedStage 'secrets-scan' 'secrets-scan' 'npm run secrets:scan'
    Invoke-LoggedStage 'production-revision-tests' 'production-revision' 'npm run test:production-revision'
    Invoke-LoggedStage 'backup-inventory-tests' 'backup-inventory' 'npm run test:backup:inventory'
    Invoke-LoggedStage 'production-operations-tests' 'production-operations' 'bash -n scripts/production-server.sh && node --test scripts/production-ops.test.mjs scripts/production-ci.test.mjs scripts/production-compose.test.mjs scripts/production-image-provenance.test.mjs scripts/ghcr-transport-integration.test.mjs scripts/ghcr-publication.test.mjs scripts/ghcr-evidence.test.mjs'
    Invoke-LoggedStage 'public-site-tests' 'public-site-tests' 'npm run test:public-site'
  }
  if ($UnitOnly -or (-not $E2EOnly -and -not $IntegrationOnly)) {
    Invoke-LoggedStage 'unit-tests' 'unit-tests' 'npm run test:unit'
  }
  if (-not $E2EOnly -and -not $UnitOnly) {
    $integrationEnvironment = @('--env', ('DATABASE_URL=' + $urls.runtime), '--env', ('VIRKI_INTEGRATION_DATABASE_URL=' + $urls.integration), '--env', 'VIRKI_CORE_TEST_DATABASE_CONFIRM=disposable')
    Invoke-LoggedStage 'integration-tests' 'integration-tests' 'npm run test:integration' $integrationEnvironment
  }
  if (-not $IntegrationOnly -and -not $UnitOnly) {
    $playwrightCommand = @('bash', '-lc', 'npm run test:e2e -- "$@" > /tmp/browser-e2e.log 2>&1; status=$?; tail -n 80 /tmp/browser-e2e.log; exit $status', 'virki-e2e')
    if ($PlaywrightArguments.Count -gt 0) { $playwrightCommand += $PlaywrightArguments }
    $e2eEnvironment = @('--env', ('DATABASE_URL=' + $urls.runtime), '--env', ('VIRKI_E2E_DATABASE_URL=' + $urls.e2e), '--env', ('VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL=' + $urls.audit), '--env', 'VIRKI_CORE_TEST_DATABASE_CONFIRM=disposable')
    Invoke-Stage 'browser-e2e' $playwrightCommand $e2eEnvironment
  }
  if (-not $E2EOnly -and -not $IntegrationOnly -and -not $UnitOnly) {
    Invoke-LoggedStage 'lint' 'lint' 'npm run lint'
    Invoke-LoggedStage 'typecheck' 'typecheck' 'npm run typecheck'
    Invoke-LoggedStage 'prisma-validate' 'prisma-validate' 'npm run prisma:validate'
    Invoke-LoggedStage 'build' 'build' 'npm run build'
    Invoke-LoggedStage 'windows-ca-helper-tests' 'windows-ca-helper' 'node --test scripts/e2e/windows-ca-trust.test.mjs scripts/e2e/runtime-artifacts.test.mjs'
    Invoke-Stage 'worktree-diff-check' @('git', 'diff', '--check')
  }

  Write-Output "`nLocal validation results:"
  $script:results
  if (@($script:results | Where-Object { $_ -notmatch '=0$' }).Count -gt 0) { exit 1 }
} finally {
  Write-Output "`nRemoving the temporary PostgreSQL container, Playwright runner, private network, and Git snapshot."
  if ($runnerName) { & docker rm --force --volumes $runnerName 2>$null | Out-Null }
  if ($databaseName) { & docker rm --force --volumes $databaseName 2>$null | Out-Null }
  if ($networkName) { & docker network rm $networkName 2>$null | Out-Null }
  $resolvedSnapshot = [System.IO.Path]::GetFullPath($snapshotDirectory)
  if ($resolvedSnapshot.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -and $resolvedSnapshot -ne $tempRoot -and (Test-Path -LiteralPath $resolvedSnapshot)) {
    Remove-Item -LiteralPath $resolvedSnapshot -Recurse -Force
  }
  Write-Output 'Temporary resources removed.'
}
