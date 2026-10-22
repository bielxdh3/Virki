param(
  [switch]$E2EOnly,
  [switch]$IntegrationOnly,
  [switch]$UnitOnly,
  [string]$IntegrationTestFile,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$PlaywrightArguments = @()
)

$ErrorActionPreference = 'Stop'

function Get-FileSha256([string]$LiteralPath) {
  $algorithm = [System.Security.Cryptography.SHA256]::Create()
  $stream = [System.IO.File]::OpenRead($LiteralPath)
  try {
    return [System.BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
  } finally {
    $stream.Dispose()
    $algorithm.Dispose()
  }
}

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
# Resolve no executable or daemon through PATH, active context, or Docker
# configuration. The signed binary resides under the protected Program Files
# tree, and each invocation names the local Linux Desktop pipe explicitly.
if ($env:DOCKER_HOST -or $env:DOCKER_CONTEXT -or $env:DOCKER_CONFIG) {
  throw 'Isolated E2E requires an unoverridden local Docker Desktop Linux context.'
}
if (-not [System.Environment]::OSVersion.Platform.Equals([System.PlatformID]::Win32NT)) {
  throw 'Isolated E2E is restricted to the Windows Docker Desktop local runner.'
}
$script:dockerCli = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
$script:dockerHost = 'npipe:////./pipe/dockerDesktopLinuxEngine'
if (-not (Test-Path -LiteralPath $script:dockerCli -PathType Leaf)) {
  throw 'Isolated E2E requires the installed Docker Desktop executable.'
}
$signature = Get-AuthenticodeSignature -LiteralPath $script:dockerCli
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
    -not $signature.SignerCertificate.Subject.StartsWith('CN=Docker Inc,', [System.StringComparison]::OrdinalIgnoreCase)) {
  throw 'Isolated E2E requires a valid Docker Inc-signed Desktop executable.'
}
function Invoke-PinnedDocker {
  # Windows PowerShell 5.1 interprets literal Docker/Node flags such as `-e`
  # as abbreviated PowerShell common parameters when a param() exists, even
  # with ValueFromRemainingArguments. Use only the unbound argument array.
  & $script:dockerCli --host $script:dockerHost @args
}
function Invoke-DockerObservation {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$DockerArguments)
  # Windows PowerShell 5 may promote stderr from an expected nonzero Docker
  # inspect into a terminating error under Stop. Capture the result and code,
  # then let callers accept only exact expected missing-object diagnostics.
  $priorPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $lines = @(Invoke-PinnedDocker @DockerArguments 2>&1 | ForEach-Object { $_.ToString() })
    return [pscustomobject]@{ Status = $LASTEXITCODE; Output = ($lines -join "`n") }
  } finally {
    $ErrorActionPreference = $priorPreference
  }
}
$dockerProbe = Invoke-PinnedDocker version --format '{{.Server.Os}}|{{.Server.Arch}}' 2>$null
if ($LASTEXITCODE -ne 0 -or ($dockerProbe | Out-String).Trim() -cne 'linux|amd64') {
  throw 'Isolated E2E refuses an unverified local Linux/amd64 Docker endpoint.'
}
$repositoryBranch = (& git -C $repoRoot branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or $repositoryBranch -notmatch '^[A-Za-z0-9._/-]{1,240}$') {
  throw 'The isolated Docker snapshot requires a named local branch with a supported ref name.'
}
$runId = [Guid]::NewGuid().ToString('N')
$evidenceRoot = Join-Path $repoRoot '.virki-mission-tmp/isolated-runs'
$runEvidenceDirectory = Join-Path $evidenceRoot $runId
$evidenceIgnore = (& git -C $repoRoot check-ignore --quiet '.virki-mission-tmp/isolated-runs')
if ($LASTEXITCODE -ne 0) { throw 'The isolated run evidence directory must be Git-ignored.' }
New-Item -ItemType Directory -Path $runEvidenceDirectory -ErrorAction Stop | Out-Null
$productionOperationsEvidencePath = Join-Path $runEvidenceDirectory 'production-operations-tests.tap.log'
$unitTestsEvidencePath = Join-Path $runEvidenceDirectory 'unit-tests.tap.log'
$integrationTestsEvidencePath = Join-Path $runEvidenceDirectory 'integration-tests.tap.log'
$bootstrapVirginTestsEvidencePath = Join-Path $runEvidenceDirectory 'bootstrap-virgin-tests.tap.log'
$browserE2EEvidencePath = Join-Path $runEvidenceDirectory 'browser-e2e-output.log'
$runManifestPath = Join-Path $runEvidenceDirectory 'run-manifest.json'
$dockerMutationJournalPath = Join-Path $runEvidenceDirectory 'docker-mutations.jsonl'
$runStartedAt = [DateTimeOffset]::UtcNow
$tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$snapshotDirectory = Join-Path $tempRoot ('virki-e2e-' + $runId)
$snapshotUntrackedDirectory = Join-Path $snapshotDirectory 'untracked'
$bundlePath = Join-Path $snapshotDirectory 'repository.bundle'
$stagedPatchPath = Join-Path $snapshotDirectory 'staged.patch'
$workingPatchPath = Join-Path $snapshotDirectory 'working-tree.patch'
$networkName = 'virki-e2e-' + $runId
$bootstrapNetworkName = 'virki-e2e-bootstrap-' + $runId
$databaseName = 'virki-e2e-postgres-' + $runId
$runnerName = 'virki-e2e-runner-' + $runId
$playwrightBrowserImage = 'mcr.microsoft.com/playwright@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27'
$browserSeedName = 'virki-e2e-browser-seed-' + $runId
$browserExecutablePath = '/ms-playwright/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell'
$browserVolumeMount = $null
$script:dockerOwnerLabel = 'org.virki.e2e.owner=' + $runId
$script:dockerResourceNames = @{
  network = $networkName
  bootstrapNetwork = $bootstrapNetworkName
  database = $databaseName
  runner = $runnerName
  browserSeed = $browserSeedName
}
$script:ownedDockerIds = @{
  network = $null
  bootstrapNetwork = $null
  database = $null
  runner = $null
  browserSeed = $null
}
$script:browserAnonymousVolume = $null
$script:dockerMutationUncertain = $false
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
$script:stageManifest = [System.Collections.Generic.List[object]]::new()
$script:ownedResources = [ordered]@{
  snapshot = $false
  network = $false
  bootstrapNetwork = $false
  database = $false
  runner = $false
  browserSeed = $false
}
$script:runFailed = $false
$script:nodeVersion = $null
$script:npmVersion = $null
$script:browserImage = $null
$script:playwrightVersion = $null
$script:browserRevision = $null
$script:browserVersion = $null
$script:stagedPatchSha256 = $null
$script:workingTreePatchSha256 = $null
$script:untrackedFileEvidence = @()
$script:unitTestFailures = @()
$script:productionOperationsFailures = @()
$script:integrationTestFailures = @()
$script:runnerName = $runnerName
$sourceHead = (& git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not read the source HEAD for the isolated run manifest.' }
Write-Output ("ISOLATED_RUN_ID=" + $runId)
Write-Output ("SOURCE_BRANCH=" + $repositoryBranch)
Write-Output ("SOURCE_HEAD=" + $sourceHead)

# A successful CLI status alone is not ownership evidence. Record the intent
# durably BEFORE creating or removing any resource. If an ACK or inspection
# fails, retain the record for manual reconciliation; never delete by a name.
function Write-DockerMutationJournal {
  param([string]$State, [string]$Kind, [string]$Name, [string]$Identity = '')
  $record = [ordered]@{
    timestampUtc = [DateTimeOffset]::UtcNow.ToString('o')
    owner = $runId
    state = $State
    kind = $Kind
    name = $Name
    identity = $Identity
  }
  $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Compress) + "`n")
  $stream = [System.IO.FileStream]::new($dockerMutationJournalPath,
    [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
  try {
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
  } finally {
    $stream.Dispose()
  }
}

function Assert-OwnedDockerIdentity {
  param([string]$Kind, [string]$Name, [string]$Lookup, [string]$ExpectedId = '')
  $dockerKind = if ($Kind -in @('network', 'bootstrapNetwork')) { 'network' } else { 'container' }
  $observation = Invoke-DockerObservation $dockerKind inspect $Lookup
  if ($observation.Status -ne 0) { throw "Owned Docker $Kind inspection failed; reconcile using the mutation journal." }
  try { $entries = @(($observation.Output.Trim() | ConvertFrom-Json -ErrorAction Stop)) }
  catch { throw 'Owned Docker inspection returned malformed JSON.' }
  if ($entries.Count -ne 1) { throw 'Owned Docker inspection must identify exactly one resource.' }
  $entry = $entries[0]
  $labels = if ($dockerKind -eq 'container') { $entry.Config.Labels } else { $entry.Labels }
  $observedName = if ($dockerKind -eq 'container') { '/' + $Name } else { $Name }
  if ($entry.Name -cne $observedName -or $null -eq $labels -or
      $labels.'org.virki.e2e.owner' -cne $runId) {
    throw "Docker resource $Kind failed owner/name verification."
  }
  if ($entry.Id -cnotmatch '^[a-f0-9]{64}$' -or $entry.Id -cne $ExpectedId) {
    throw "Docker resource $Kind changed its immutable identity."
  }
  return $entry
}

function Invoke-CreateOwnedDockerResource {
  param([string]$Kind, [string]$Name, [string[]]$DockerArguments)
  if ($script:ownedResources[$Kind] -or $script:dockerMutationUncertain) {
    throw 'Refusing repeated or uncertain Docker creation.'
  }
  Write-DockerMutationJournal 'MUTATION_PENDING' $Kind $Name
  try {
    $answer = @(Invoke-PinnedDocker @DockerArguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Docker $Kind creation ACK is uncertain." }
    $identifier = ($answer | Out-String).Trim()
    if ($identifier -cnotmatch '^[a-f0-9]{64}$') { throw 'Docker create did not return an immutable resource ID.' }
    $null = Assert-OwnedDockerIdentity $Kind $Name $identifier $identifier
    $script:ownedDockerIds[$Kind] = $identifier
    $script:ownedResources[$Kind] = $true
    Write-DockerMutationJournal 'MUTATION_ACKNOWLEDGED' $Kind $Name $identifier
    return $identifier
  } catch {
    $script:dockerMutationUncertain = $true
    Write-DockerMutationJournal 'RECONCILIATION_REQUIRED' $Kind $Name
    throw
  }
}

function Invoke-OwnedDockerCleanup {
  param([string]$Kind)
  if (-not $script:ownedResources[$Kind]) { return }
  $name = $script:dockerResourceNames[$Kind]
  $id = $script:ownedDockerIds[$Kind]
  if (-not $id) { throw "Owned Docker $Kind has no verified resource identity." }
  $null = Assert-OwnedDockerIdentity $Kind $name $id $id
  Write-DockerMutationJournal 'REMOVE_PENDING' $Kind $name $id
  try {
    switch ($Kind) {
      { $_ -in @('network', 'bootstrapNetwork') } { $null = @(Invoke-PinnedDocker network rm $id 2>&1) }
      # Removing the seed by its immutable container ID also removes only its
      # Docker-managed anonymous volume. Never invoke `volume rm <name>`:
      # a mutable volume name could be rebound to a foreign volume after inspect.
      'browserSeed' { $null = @(Invoke-PinnedDocker container rm --force --volumes $id 2>&1) }
      default { $null = @(Invoke-PinnedDocker container rm --force --volumes $id 2>&1) }
    }
    if ($LASTEXITCODE -ne 0) { throw "Docker $Kind removal ACK is uncertain." }
    $dockerKind = if ($Kind -in @('network', 'bootstrapNetwork')) { 'network' } else { 'container' }
    $postRemoval = Invoke-DockerObservation $dockerKind inspect $id
    # Docker Desktop returns [] plus "network <immutable ID> not found" for
    # a removed network, rather than "No such network". Require a precise
    # diagnostic for THIS ID so an arbitrary inspection failure cannot become
    # a fabricated absence or a successful cleanup receipt.
    $quotedId = [regex]::Escape($id)
    $expectedMissingNetwork = $dockerKind -eq 'network' -and $postRemoval.Output -match (
      '(?is)^\s*\[\]\s*Error response from daemon: network ' + $quotedId + ' not found\s*$')
    $expectedMissingObject = $postRemoval.Output -match (
      '(?is)^\s*(?:\[\]\s*)?(?:Error response from daemon:\s*)?(?:Error:\s*)?No such (?:object|container|network): ' + $quotedId + '\s*$')
    if ($postRemoval.Status -eq 0 -or -not ($expectedMissingNetwork -or $expectedMissingObject)) {
      throw "Docker $Kind absence could not be confirmed."
    }
    if ($Kind -eq 'browserSeed' -and $script:browserAnonymousVolume) {
      $volumeAfter = Invoke-DockerObservation volume inspect $script:browserAnonymousVolume
      if ($volumeAfter.Status -eq 0 -or $volumeAfter.Output -notmatch '(?i)\bno such volume\b') {
        throw 'Docker-managed anonymous browser volume was not removed with the owned seed container.'
      }
    }
    Write-DockerMutationJournal 'REMOVE_CONFIRMED' $Kind $name $id
    $script:ownedResources[$Kind] = $false
  } catch {
    $script:dockerMutationUncertain = $true
    Write-DockerMutationJournal 'RECONCILIATION_REQUIRED' $Kind $name $id
    throw
  }
}

$selectedStageCount = 0
if ($E2EOnly) { $selectedStageCount++ }
if ($IntegrationOnly) { $selectedStageCount++ }
if ($UnitOnly) { $selectedStageCount++ }
if ($selectedStageCount -gt 1) { throw 'Choose only one isolated runner stage.' }
if ($IntegrationTestFile) {
  if (-not $IntegrationOnly) { throw 'An isolated integration test file requires -IntegrationOnly.' }
  if ($IntegrationTestFile -notmatch '^(apps|packages)/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\.integration\.test\.ts$') {
    throw 'The isolated integration test file must be a repository-relative *.integration.test.ts path under apps/ or packages/.'
  }
  $integrationTestPath = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $IntegrationTestFile.Replace('/', [System.IO.Path]::DirectorySeparatorChar)))
  $repoPrefix = [System.IO.Path]::GetFullPath($repoRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
  if (-not $integrationTestPath.StartsWith($repoPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $integrationTestPath -PathType Leaf)) {
    throw 'The isolated integration test file must resolve to a file inside this repository.'
  }
}

function Invoke-Stage {
  param([string]$Name, [string[]]$Command, [string[]]$Environment = @(), [string]$EvidenceLogPath)
  Write-Output "`n[$Name]"
  $startedAt = [DateTimeOffset]::UtcNow
  $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
  if ($EvidenceLogPath) {
    $stageOutput = @(Invoke-PinnedDocker exec --workdir /workspace @Environment $script:runnerName @Command 2>&1)
    $exitCode = $LASTEXITCODE
    $stageLines = [string[]]@($stageOutput | ForEach-Object { $_.ToString() })
    [System.IO.File]::WriteAllLines($EvidenceLogPath, $stageLines, [System.Text.UTF8Encoding]::new($false))
    foreach ($line in $stageLines) { Write-Output $line }
  } else {
    Invoke-PinnedDocker exec --workdir /workspace @Environment $script:runnerName @Command
    $exitCode = $LASTEXITCODE
  }
  $stopwatch.Stop()
  $finishedAt = [DateTimeOffset]::UtcNow
  $script:results.Add($Name + '=' + $exitCode)
  $script:stageManifest.Add([ordered]@{
    name = $Name
    startedUtc = $startedAt.ToString('o')
    finishedUtc = $finishedAt.ToString('o')
    durationMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
    exitCode = $exitCode
  })
  Write-Output ("[RESULT] {0} exit={1} durationMs={2}" -f $Name, $exitCode, [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3))
}

function Invoke-LoggedStage {
  param([string]$Name, [string]$LogName, [string]$CommandText, [string[]]$Environment = @(), [string]$EvidenceLogPath, [switch]$CaptureFullOutput)
  $logOutputCommand = if ($CaptureFullOutput) { 'cat' } else { 'tail -n 80' }
  # Group the ENTIRE stage before redirection. Without parentheses, A && B
  # sends only B to the log, so an A failure leaves no file and tail masks
  # the actual error. Preserve the true compound command exit status.
  $shellCommand = '( ' + $CommandText + ' ) > /tmp/' + $LogName + '.log 2>&1; status=$?; ' + $logOutputCommand + ' /tmp/' + $LogName + '.log; exit $status'
  Invoke-Stage -Name $Name -Command @('bash', '-lc', $shellCommand) -Environment $Environment -EvidenceLogPath $EvidenceLogPath
}

function Get-TapFailureManifest {
  param([string]$Path)
  $failures = [System.Collections.Generic.List[object]]::new()
  $lineNumber = 0
  foreach ($line in [System.IO.File]::ReadLines($Path)) {
    $lineNumber++
    if ($line -match '^(?<indent>\s*)not ok (?<number>\d+) - (?<name>.*)$') {
      $failures.Add([ordered]@{
        line = $lineNumber
        nestingIndent = $Matches.indent.Length
        testNumber = [int]$Matches.number
        name = $Matches.name
      })
    }
  }
  return @($failures)
}

function Assert-RunnerFileSha256 {
  param([string]$ContainerPath, [string]$ExpectedSha256, [string]$Description)
  $hashOutput = Invoke-PinnedDocker exec $script:runnerName sha256sum -- $ContainerPath
  if ($LASTEXITCODE -ne 0) { throw ("Could not verify the copied " + $Description + " in the Linux runner.") }
  $hashFields = [string]$hashOutput -split '\s+'
  $actualSha256 = $hashFields[0]
  if ($actualSha256 -notmatch '^[A-Fa-f0-9]{64}$' -or $actualSha256 -ine $ExpectedSha256) {
    throw ("The copied " + $Description + " does not match its recorded source hash.")
  }
}

try {
  New-Item -ItemType Directory -Path $snapshotDirectory -ErrorAction Stop | Out-Null
  $script:ownedResources.snapshot = $true
  & git -C $repoRoot bundle create $bundlePath --all
  if ($LASTEXITCODE -ne 0) { throw 'Could not create a temporary Git bundle.' }
  & git -C $repoRoot diff --cached --binary ("--output=" + $stagedPatchPath)
  if ($LASTEXITCODE -ne 0) { throw 'Could not snapshot staged worktree changes.' }
  & git -C $repoRoot diff --binary ("--output=" + $workingPatchPath)
  if ($LASTEXITCODE -ne 0) { throw 'Could not snapshot unstaged worktree changes.' }
  $script:stagedPatchSha256 = Get-FileSha256 -LiteralPath $stagedPatchPath
  $script:workingTreePatchSha256 = Get-FileSha256 -LiteralPath $workingPatchPath
  $untrackedFiles = @(& git -C $repoRoot ls-files --others --exclude-standard)
  if ($LASTEXITCODE -ne 0) { throw 'Could not inventory nonignored untracked files.' }
  $allowedUntracked = @(
    'apps/hub/src/app/admin/accounts/account-state-control.test.tsx',
    'apps/hub/src/app/admin/accounts/account-state-control.tsx',
    'apps/hub/src/app/admin/accounts/account-state-policy.ts',
    'scripts/legacy-data-inventory.test.ts',
    'scripts/legacy-data-inventory.ts',
    'apps/hub/src/app/admin/accounts/account-state-policy.ts',
    'apps/hub/src/app/recover/recovery-completion-form.tsx',
    'apps/hub/src/app/protected-page-lifecycle.tsx',
    'apps/hub/src/lib/login-redirect.test.ts',
    'apps/hub/src/lib/login-redirect.ts',
    'apps/hub/src/lib/sensitive-page-lifecycle.test.ts',
    'apps/hub/src/lib/sensitive-page-lifecycle.ts',
    'apps/hub/src/lib/use-sensitive-form-action.ts',
    'apps/issuer/src/interaction-error.test.ts',
    'apps/issuer/src/interaction-error.ts',
    'apps/issuer/src/provider-audit.test.ts',
    'apps/issuer/src/provider-audit.ts',
    'apps/public-site/src/app/public-origin.test.ts',
    'apps/public-site/src/app/public-origin.ts',
    'docs/gate-closure-report.md',
    'docs/final-local-security-gates-report.md',
    'docs/index-query-plan-evidence.md',
    'docs/legacy-data-closure-plan.md',
    'docs/security-triage-a21-review-2026-10-20.md',
    'docs/security-triage-closeout-2026-10-20.md',
    'docs/superpowers/plans/2026-10-19-virki-final-four-findings.md',
    'e2e/recovery-invitation.spec.mts',
    'packages/auth/src/elevation-authorization.ts',
    'packages/auth/src/legacy-data-inventory.integration.test.ts',
    'packages/database/prisma/migrations/20261019120000_runtime_audit_write_boundary/migration.sql',
    'scripts/admin-elevation-boundary.test.mjs',
    'scripts/e2e/start-production-hub.mjs',
    'scripts/e2e/low05-diagnostics.mjs',
    'scripts/e2e/low05-diagnostics.test.mjs',
    'scripts/e2e/oidc-private-config.mjs',
    'scripts/e2e/redact-browser-e2e-log.mjs',
    'scripts/e2e/run-isolated-linux-docker.ps1',
    'scripts/e2e/run-e2e.mjs',
    'scripts/e2e/run-e2e.test.mjs'
  )
  if ($untrackedFiles | Where-Object { $_ -notin $allowedUntracked }) {
    throw 'The Docker E2E snapshot found an unexpected untracked file; review it before copying.'
  }
  New-Item -ItemType Directory -Path $snapshotUntrackedDirectory -Force -ErrorAction Stop | Out-Null
  foreach ($relativePath in $untrackedFiles) {
    $snapshotPath = Join-Path $snapshotUntrackedDirectory $relativePath
    $snapshotParent = Split-Path -Parent $snapshotPath
    New-Item -ItemType Directory -Path $snapshotParent -Force -ErrorAction Stop | Out-Null
    Copy-Item -LiteralPath (Join-Path $repoRoot $relativePath) -Destination $snapshotPath -ErrorAction Stop
  }
  $untrackedEvidence = @(
    foreach ($relativePath in $untrackedFiles) {
      $untrackedPath = Join-Path $snapshotUntrackedDirectory $relativePath
      [ordered]@{
        path = $relativePath.Replace('\', '/')
        sha256 = Get-FileSha256 -LiteralPath $untrackedPath
      }
    }
  )
  $script:untrackedFileEvidence = @($untrackedEvidence | Sort-Object -Property path -Culture 'en-US' -CaseSensitive)

  if (-not $IntegrationOnly -and -not $UnitOnly) {
    $browserImageId = Invoke-PinnedDocker image inspect --format '{{.Id}}' $playwrightBrowserImage 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $browserImageId) { throw 'The pinned Playwright browser image is not installed locally; refusing to download browser binaries.' }
    # An anonymous engine-owned volume is attached to an owned seed container.
    # Docker removes it atomically via `container rm --volumes <immutable-id>`
    # after the runner is removed; we never delete any named volume.
    $browserSeedName = Invoke-CreateOwnedDockerResource 'browserSeed' $browserSeedName @(
      'create', '--name', $browserSeedName, '--network', 'none', '--label', $script:dockerOwnerLabel,
      '--mount', 'type=volume,target=/ms-playwright/chromium_headless_shell-1243',
      '--entrypoint', '/bin/bash', $playwrightBrowserImage, '-lc', 'sleep infinity')
    $seedRecord = Assert-OwnedDockerIdentity 'browserSeed' $script:dockerResourceNames.browserSeed $browserSeedName $browserSeedName
    $seedMounts = @($seedRecord.Mounts)
    if ($seedMounts.Count -ne 1 -or $seedMounts[0].Type -cne 'volume' -or
        $seedMounts[0].Destination -cne '/ms-playwright/chromium_headless_shell-1243' -or
        $seedMounts[0].Name -cnotmatch '^[a-f0-9]{64}$') {
      throw 'Disposable browser image failed anonymous volume mount ownership verification.'
    }
    $script:browserAnonymousVolume = $seedMounts[0].Name
    $browserVolumeMount = 'type=volume,source=' + $script:browserAnonymousVolume + ',target=/ms-playwright/chromium_headless_shell-1243'
    Invoke-PinnedDocker start $browserSeedName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the temporary Chromium cache volume.' }
    Invoke-PinnedDocker exec $browserSeedName test -x $browserExecutablePath
    if ($LASTEXITCODE -ne 0) { throw 'The pinned Playwright image does not contain the expected Chromium headless shell.' }
    $script:browserImage = $playwrightBrowserImage
  }

  $networkName = Invoke-CreateOwnedDockerResource 'network' $networkName @(
    'network', 'create', '--driver', 'bridge', '--internal', '--label', $script:dockerOwnerLabel,
    $networkName)
  # Dependency installation needs egress, but must not share Docker's ambient
  # default bridge with existing host containers.
  $bootstrapNetworkName = Invoke-CreateOwnedDockerResource 'bootstrapNetwork' $bootstrapNetworkName @(
    'network', 'create', '--driver', 'bridge', '--label', $script:dockerOwnerLabel,
    $bootstrapNetworkName)
  $databaseName = Invoke-CreateOwnedDockerResource 'database' $databaseName @(
    'create', '--name', $databaseName, '--network', $networkName,
    '--network-alias', 'postgres', '--label', $script:dockerOwnerLabel,
    '--tmpfs', '/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m',
    '--health-cmd', 'pg_isready -h 127.0.0.1 -U virki_bootstrap -d virki_e2e_test',
    '--health-interval', '1s', '--health-timeout', '3s', '--health-retries', '90',
    '--env', 'POSTGRES_DB=virki_e2e_test', '--env', 'POSTGRES_USER=virki_bootstrap',
    '--env', ("POSTGRES_PASSWORD=" + $passwords.bootstrap),
    '--env', ("VIRKI_RUNTIME_DB_PASSWORD=" + $passwords.runtime),
    '--env', ("VIRKI_MIGRATOR_DB_PASSWORD=" + $passwords.migrator),
    '--env', ("VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD=" + $passwords.audit),
    '--env', ("VIRKI_E2E_DATABASE_PASSWORD=" + $passwords.test),
    'postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24')

  Invoke-PinnedDocker cp (Join-Path $repoRoot 'infra/postgres-init/10-virki-database-roles.sh') ($databaseName + ':/docker-entrypoint-initdb.d/10-virki-database-roles.sh') | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the database role initializer.' }
  Invoke-PinnedDocker cp (Join-Path $repoRoot 'scripts/e2e/20-virki-e2e-runtime-test-role.sh') ($databaseName + ':/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh') | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the E2E role initializer.' }
  Invoke-PinnedDocker start $databaseName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the disposable PostgreSQL container.' }

  $databaseReady = $false
  for ($attempt = 0; $attempt -lt 90; $attempt++) {
    $health = (Invoke-PinnedDocker inspect --format '{{.State.Health.Status}}' $databaseName 2>$null).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not inspect the disposable PostgreSQL health state.' }
    if ($health -eq 'healthy') { $databaseReady = $true; break }
    if ($health -eq 'unhealthy') { break }
    Start-Sleep -Seconds 1
  }
  if (-not $databaseReady) {
    Invoke-PinnedDocker logs $databaseName
    throw 'Disposable PostgreSQL did not become healthy within 90 seconds.'
  }

  $runnerCreateArguments = @('create', '--name', $runnerName, '--network', $bootstrapNetworkName,
    '--label', $script:dockerOwnerLabel)
  if ($env:VIRKI_E2E_HUB_MODE -eq 'production') {
    $runnerCreateArguments += @('--add-host', 'access.e2e.invalid:127.0.0.1')
  }
  if ($script:ownedResources.browserSeed -and $script:browserAnonymousVolume) {
    $runnerCreateArguments += @('--mount', ($browserVolumeMount + ',readonly'), '--env', ('VIRKI_E2E_CHROMIUM_EXECUTABLE_PATH=' + $browserExecutablePath))
  }
  $runnerCreateArguments += @('--entrypoint', '/bin/bash', 'node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8', '-lc', 'sleep infinity')
  $runnerName = Invoke-CreateOwnedDockerResource 'runner' $runnerName $runnerCreateArguments
  $script:runnerName = $runnerName
  Invoke-PinnedDocker cp $bundlePath ($runnerName + ':/tmp/virki.bundle')
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the temporary Git bundle.' }
  Invoke-PinnedDocker cp $stagedPatchPath ($runnerName + ':/tmp/staged.patch')
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the staged worktree patch.' }
  Invoke-PinnedDocker cp $workingPatchPath ($runnerName + ':/tmp/working-tree.patch')
  if ($LASTEXITCODE -ne 0) { throw 'Could not copy the unstaged worktree patch.' }
  Invoke-PinnedDocker start $runnerName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the isolated Playwright runner.' }
  Assert-RunnerFileSha256 '/tmp/staged.patch' $script:stagedPatchSha256 'staged patch'
  Assert-RunnerFileSha256 '/tmp/working-tree.patch' $script:workingTreePatchSha256 'unstaged patch'
  # Bootstrap dependencies only on the dedicated egress network. Do not
  # attach the private database network until all external package installs
  # finish, or untrusted postinstall scripts could reach both networks.
  Invoke-PinnedDocker exec $runnerName bash -lc 'apt-get update -qq && apt-get install -y --no-install-recommends git libnss3-tools'
  if ($LASTEXITCODE -ne 0) { throw 'Could not install Linux Git and Chromium NSS tooling.' }
  $nodeVersion = (Invoke-PinnedDocker exec $runnerName node --version).Trim()
  $npmVersion = (Invoke-PinnedDocker exec $runnerName npm --version).Trim()
  $script:nodeVersion = $nodeVersion
  $script:npmVersion = $npmVersion
  Write-Output "Linux runtime: Node $nodeVersion, npm $npmVersion"
  if ($nodeVersion -notmatch '^v22\.' -or [version]$npmVersion -lt [version]'10.9.3' -or [version]$npmVersion -ge [version]'11.0.0') {
    throw 'The Linux runner does not satisfy the repository Node/npm engines.'
  }
  Invoke-PinnedDocker exec $runnerName git clone --branch $repositoryBranch /tmp/virki.bundle /workspace
  if ($LASTEXITCODE -ne 0) { throw 'Could not clone the temporary Git snapshot.' }
  $clonedHeadOutput = Invoke-PinnedDocker exec --workdir /workspace $runnerName git rev-parse HEAD
  if ($LASTEXITCODE -ne 0) { throw 'Could not read the cloned source HEAD.' }
  $clonedHead = $clonedHeadOutput.Trim()
  if ($clonedHead -cne $sourceHead) { throw 'The cloned snapshot does not match the source HEAD captured for this run.' }
  Invoke-PinnedDocker exec --workdir /workspace $runnerName bash -lc 'if [ -s /tmp/staged.patch ]; then git apply --binary /tmp/staged.patch; fi; if [ -s /tmp/working-tree.patch ]; then git apply --binary /tmp/working-tree.patch; fi'
  if ($LASTEXITCODE -ne 0) { throw 'Could not apply the current worktree changes to the temporary clone.' }
  foreach ($relativePath in $untrackedFiles) {
    $relativeDirectory = Split-Path -Parent $relativePath
    if ($relativeDirectory) {
      Invoke-PinnedDocker exec $runnerName mkdir -p ('/workspace/' + $relativeDirectory.Replace('\', '/'))
      if ($LASTEXITCODE -ne 0) { throw 'Could not prepare a parent directory for an untracked snapshot file.' }
    }
    $snapshotPath = Join-Path $snapshotUntrackedDirectory $relativePath
    Invoke-PinnedDocker cp $snapshotPath ($runnerName + ':/workspace/' + $relativePath.Replace('\', '/')) | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not copy an untracked test file into the temporary clone.' }
    $relativeManifestPath = $relativePath.Replace('\', '/')
    $expectedFile = @($script:untrackedFileEvidence | Where-Object { $_.path -eq $relativeManifestPath })[0]
    if ($null -eq $expectedFile) { throw 'The untracked snapshot is missing its recorded content hash.' }
    Assert-RunnerFileSha256 ('/workspace/' + $relativeManifestPath) $expectedFile.sha256 ('untracked file ' + $relativeManifestPath)
  }

  Invoke-PinnedDocker exec $runnerName bash -lc 'mkdir -p /workspace/packages/database/generated /workspace/prisma/generated /workspace/apps/hub/.next /workspace/apps/public-site/.next /workspace/apps/issuer/.next /workspace/test-results /workspace/playwright-report'
  if ($LASTEXITCODE -ne 0) { throw 'Could not prepare isolated workspace output directories.' }
  Invoke-PinnedDocker exec --workdir /workspace $runnerName npm ci
  if ($LASTEXITCODE -ne 0) { throw 'Locked Linux dependency installation failed.' }
  Invoke-Stage 'tooling-policy-dependencies' @('bash', '-lc', 'npm ls @prisma/config deepmerge-ts --all')
  Invoke-LoggedStage 'tooling-policy-tests' 'tooling-policy' 'node scripts/tooling-audit-policy.mjs && node --test scripts/tooling-audit-policy.test.mjs'
  if (-not $IntegrationOnly -and -not $UnitOnly) {
    $script:playwrightVersion = (Invoke-PinnedDocker exec --workdir /workspace $runnerName npx playwright --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $script:playwrightVersion -ne 'Version 1.63.0') { throw 'The installed Playwright package does not match the preinstalled browser image.' }
    $script:browserRevision = (Invoke-PinnedDocker exec --workdir /workspace $runnerName node -e "const b=require('./node_modules/playwright-core/browsers.json').browsers.find((x)=>x.name==='chromium-headless-shell');if(!b)process.exit(1);process.stdout.write(String(b.revision))").Trim()
    if ($LASTEXITCODE -ne 0 -or $script:browserRevision -ne '1243') { throw 'The locked Playwright browser revision does not match the preinstalled image.' }
    Invoke-LoggedStage 'chromium-dependencies' 'chromium-dependencies' 'npx playwright install-deps chromium'
    if ($script:ownedResources.browserSeed -and $script:browserAnonymousVolume) {
      $script:browserVersion = (Invoke-PinnedDocker exec $runnerName $browserExecutablePath --version).Trim()
      if ($LASTEXITCODE -ne 0 -or -not $script:browserVersion) { throw 'The preinstalled Chromium headless shell did not start.' }
      Write-Output "Chromium: $($script:browserVersion) from $playwrightBrowserImage"
    }
  }

  Invoke-PinnedDocker network disconnect $bootstrapNetworkName $runnerName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not disconnect the runner bootstrap egress network.' }
  # Docker Desktop retains the original network mode in HostConfig after
  # disconnect; preserve this empty network until its replacement attaches.
  # The container never has simultaneous bootstrap/private endpoints.
  Invoke-PinnedDocker network connect $networkName $runnerName | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not connect the runner to the private database network.' }
  Invoke-OwnedDockerCleanup 'bootstrapNetwork'
  Invoke-PinnedDocker exec --workdir /workspace --env ("DATABASE_URL=" + $urls.runtime) --env ("MIGRATION_DATABASE_URL=" + $urls.migrator) $runnerName npm run prisma:migrate:deploy
  if ($LASTEXITCODE -ne 0) { throw 'Committed migrations did not apply to the disposable database.' }
  if (-not $E2EOnly -and -not $UnitOnly) {
    # Clone the freshly migrated, untouched schema into a separate database
    # inside this run-owned tmpfs PostgreSQL. Never reset shared test data.
    Invoke-PinnedDocker exec $databaseName psql -U virki_bootstrap -d postgres -v ON_ERROR_STOP=1 --command 'CREATE DATABASE virki_bootstrap_virgin WITH TEMPLATE virki_e2e_test'
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the owned virgin bootstrap database.' }
    Invoke-PinnedDocker exec $databaseName psql -U virki_bootstrap -d postgres -v ON_ERROR_STOP=1 --command 'REVOKE ALL ON DATABASE virki_bootstrap_virgin FROM PUBLIC; GRANT CONNECT ON DATABASE virki_bootstrap_virgin TO virki_runtime_test;'
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict virgin bootstrap database CONNECT privileges.' }
  }
  Invoke-PinnedDocker exec --detach $runnerName node -e "const net=require('node:net');net.createServer(s=>{const d=net.connect(5432,'postgres');s.pipe(d);d.pipe(s)}).listen(5432,'127.0.0.1')"
  if ($LASTEXITCODE -ne 0) { throw 'Could not start the loopback-only integration database proxy.' }

  if ($env:VIRKI_E2E_HUB_MODE -eq 'production') {
    $productionHubBuildEnvironment = @(
      '--env', 'NODE_ENV=production',
      '--env', 'NEXT_TELEMETRY_DISABLED=1',
      '--env', 'VIRKI_HUB_HOSTNAME=hub.localhost',
      '--env', 'VIRKI_PORTAL_HOSTNAME=portal.localhost',
      '--env', 'VIRKI_HUB_URL=https://hub.localhost',
      '--env', 'VIRKI_PORTAL_URL=https://portal.localhost',
      '--env', 'VIRKI_OIDC_PROXY_URL=http://127.0.0.1:3003'
    )
    Invoke-LoggedStage 'production-hub-build' 'production-hub-build' 'npm run build --workspace @virki/hub' $productionHubBuildEnvironment
  }

  if (-not $E2EOnly -and -not $IntegrationOnly -and -not $UnitOnly) {
    Invoke-Stage 'runtime' @('bash', '-lc', 'node --version && npm --version && uname -s')
    Invoke-LoggedStage 'secrets-scan' 'secrets-scan' 'npm run secrets:scan'
    Invoke-LoggedStage 'production-revision-tests' 'production-revision' 'npm run test:production-revision && npm run test:offline:source-git:root'
    Invoke-LoggedStage 'backup-inventory-tests' 'backup-inventory' 'npm run test:backup:inventory'
    Invoke-LoggedStage -Name 'production-operations-tests' -LogName 'production-operations' -CommandText 'bash -n scripts/production-server.sh && node --test scripts/production-ops.test.mjs scripts/production-ci.test.mjs scripts/production-compose.test.mjs scripts/production-image-provenance.test.mjs scripts/ghcr-transport-integration.test.mjs scripts/ghcr-publication.test.mjs scripts/ghcr-evidence.test.mjs' -EvidenceLogPath $productionOperationsEvidencePath -CaptureFullOutput
    $script:productionOperationsFailures = @(Get-TapFailureManifest -Path $productionOperationsEvidencePath)
    Invoke-LoggedStage 'public-site-tests' 'public-site-tests' 'npm run test:public-site'
  }
  if ($UnitOnly -or (-not $E2EOnly -and -not $IntegrationOnly)) {
    Invoke-LoggedStage -Name 'unit-tests' -LogName 'unit-tests' -CommandText 'npm run test:unit' -EvidenceLogPath $unitTestsEvidencePath -CaptureFullOutput
    $script:unitTestFailures = @(Get-TapFailureManifest -Path $unitTestsEvidencePath)
  }
  if (-not $E2EOnly -and -not $UnitOnly) {
    $virginBootstrapUrl = $urls.integration.Replace('/virki_e2e_test?', '/virki_bootstrap_virgin?')
    if ($virginBootstrapUrl -eq $urls.integration -or $virginBootstrapUrl -cnotmatch '/virki_bootstrap_virgin\?') {
      throw 'The virgin bootstrap fixture must use its isolated database target.'
    }
    $virginBootstrapEnvironment = @('--env', ('VIRKI_INTEGRATION_DATABASE_URL=' + $virginBootstrapUrl), '--env', 'VIRKI_CORE_TEST_DATABASE_CONFIRM=disposable', '--env', 'VIRKI_BOOTSTRAP_TEST_DATABASE_CONFIRM=virgin')
    Invoke-LoggedStage -Name 'bootstrap-virgin-tests' -LogName 'bootstrap-virgin-tests' -CommandText 'npm run test:integration -- packages/auth/src/bootstrap-first-admin.integration.test.ts' -Environment $virginBootstrapEnvironment -EvidenceLogPath $bootstrapVirginTestsEvidencePath -CaptureFullOutput
    $integrationEnvironment = @('--env', ('DATABASE_URL=' + $urls.runtime), '--env', ('VIRKI_INTEGRATION_DATABASE_URL=' + $urls.integration), '--env', 'VIRKI_CORE_TEST_DATABASE_CONFIRM=disposable')
    $integrationCommand = 'npm run test:integration' + $(if ($IntegrationTestFile) { ' -- ' + $IntegrationTestFile } else { '' })
    Invoke-LoggedStage -Name 'integration-tests' -LogName 'integration-tests' -CommandText $integrationCommand -Environment $integrationEnvironment -EvidenceLogPath $integrationTestsEvidencePath -CaptureFullOutput
    $script:integrationTestFailures = @(Get-TapFailureManifest -Path $integrationTestsEvidencePath)
  }
  if (-not $IntegrationOnly -and -not $UnitOnly) {
    $playwrightCommand = @('bash', '-lc', 'set -o pipefail; npm run test:e2e -- "$@" 2>&1 | node scripts/e2e/redact-browser-e2e-log.mjs > /tmp/browser-e2e.log; status=$?; cat /tmp/browser-e2e.log; exit $status', 'virki-e2e')
    if ($PlaywrightArguments.Count -gt 0) { $playwrightCommand += $PlaywrightArguments }
    $e2eEnvironment = @('--env', ('DATABASE_URL=' + $urls.runtime), '--env', ('VIRKI_E2E_DATABASE_URL=' + $urls.e2e), '--env', ('VIRKI_E2E_AUDIT_CLEANUP_DATABASE_URL=' + $urls.migrator), '--env', 'VIRKI_CORE_TEST_DATABASE_CONFIRM=disposable')
    if ($env:VIRKI_E2E_HUB_MODE -eq 'production') { $e2eEnvironment += @('--env', 'VIRKI_E2E_HUB_MODE=production', '--env', 'VIRKI_E2E_HUB_BUILD_READY=true') }
    if ($env:VIRKI_E2E_LOW05_DIAGNOSTICS -eq 'true') { $e2eEnvironment += @('--env', 'VIRKI_E2E_LOW05_DIAGNOSTICS=true') }
    Invoke-Stage -Name 'browser-e2e' -Command $playwrightCommand -Environment $e2eEnvironment -EvidenceLogPath $browserE2EEvidencePath
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
  Write-Output ('STAGE_MANIFEST_JSON=' + ($script:stageManifest | ConvertTo-Json -Depth 4 -Compress))
  if (@($script:results | Where-Object { $_ -notmatch '=0$' }).Count -gt 0) { exit 1 }
} catch {
  $script:runFailed = $true
  throw
} finally {
  try {
    $failedStages = @($script:results | Where-Object { $_ -notmatch '=0$' })
    if ($failedStages.Count -gt 0) { $script:runFailed = $true }
    $runManifest = [ordered]@{
      runId = $runId
      sourceBranch = $repositoryBranch
      sourceHead = $sourceHead
      startedUtc = $runStartedAt.ToString('o')
      finishedUtc = [DateTimeOffset]::UtcNow.ToString('o')
      nodeVersion = $script:nodeVersion
      npmVersion = $script:npmVersion
      browserImage = $script:browserImage
      playwrightVersion = $script:playwrightVersion
      browserRevision = $script:browserRevision
      browserVersion = $script:browserVersion
      dockerMutationJournal = [System.IO.Path]::GetFileName($dockerMutationJournalPath)
      dockerMutationUncertain = $script:dockerMutationUncertain
      stagedPatchSha256 = $script:stagedPatchSha256
      workingTreePatchSha256 = $script:workingTreePatchSha256
      untrackedFiles = @($script:untrackedFileEvidence)
      unitTestsLog = if (Test-Path -LiteralPath $unitTestsEvidencePath) { [System.IO.Path]::GetFileName($unitTestsEvidencePath) } else { $null }
      unitTestsFailureCount = $script:unitTestFailures.Count
      unitTestsFailures = @($script:unitTestFailures)
      integrationTestsLog = if (Test-Path -LiteralPath $integrationTestsEvidencePath) { [System.IO.Path]::GetFileName($integrationTestsEvidencePath) } else { $null }
      integrationTestsFailureCount = $script:integrationTestFailures.Count
      integrationTestsFailures = @($script:integrationTestFailures)
      # Until verified cleanup completes, even passing stages are NOT PASS.
      exitCode = 1
      dockerCleanupVerified = $false
      failedStages = $failedStages
      stages = @($script:stageManifest)
      browserE2ELog = if (Test-Path -LiteralPath $browserE2EEvidencePath) { [System.IO.Path]::GetFileName($browserE2EEvidencePath) } else { $null }
      productionOperationsLog = [System.IO.Path]::GetFileName($productionOperationsEvidencePath)
      productionOperationsFailureCount = $script:productionOperationsFailures.Count
      productionOperationsFailures = @($script:productionOperationsFailures)
    }
    [System.IO.File]::WriteAllText($runManifestPath, ($runManifest | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
    Write-Output ('RUN_EVIDENCE_DIRECTORY=' + $runEvidenceDirectory)
  } finally {
    Write-Output "`nRemoving only independently verified owned Docker IDs."
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    foreach ($resourceKind in @('runner', 'database', 'browserSeed', 'bootstrapNetwork', 'network')) {
      try {
        Invoke-OwnedDockerCleanup $resourceKind
      } catch {
        $cleanupFailures.Add($resourceKind)
        Write-Output ("Docker cleanup needs independent reconciliation: " + $resourceKind)
      }
    }
    if ($script:ownedResources.snapshot) {
      $resolvedSnapshot = [System.IO.Path]::GetFullPath($snapshotDirectory)
      if ($resolvedSnapshot.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -and $resolvedSnapshot -ne $tempRoot -and (Test-Path -LiteralPath $resolvedSnapshot)) {
        Remove-Item -LiteralPath $resolvedSnapshot -Recurse -Force
      }
    }
    if ($script:dockerMutationUncertain -or $cleanupFailures.Count -gt 0) {
      $script:runFailed = $true
      Write-DockerMutationJournal 'RECONCILIATION_REQUIRED' 'run' $runId
      if ($null -ne $runManifest) {
        $runManifest.exitCode = 1
        $runManifest.dockerMutationUncertain = $true
        [System.IO.File]::WriteAllText($runManifestPath, ($runManifest | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
        Write-Output ('RUN_MANIFEST_JSON=' + ($runManifest | ConvertTo-Json -Depth 6 -Compress))
      }
      throw ("Isolated E2E Docker ownership is unresolved; inspect " + $dockerMutationJournalPath)
    }
    if ($null -ne $runManifest) {
      $runManifest.dockerCleanupVerified = $true
      $runManifest.exitCode = if ($script:runFailed) { 1 } else { 0 }
      [System.IO.File]::WriteAllText($runManifestPath, ($runManifest | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
      Write-Output ('RUN_MANIFEST_JSON=' + ($runManifest | ConvertTo-Json -Depth 6 -Compress))
    }
    Write-Output 'All recorded disposable Docker identities were removed.'
  }
}
