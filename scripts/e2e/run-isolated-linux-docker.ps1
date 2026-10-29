param(
  [switch]$E2EOnly,
  [switch]$IntegrationOnly,
  [switch]$UnitOnly,
  [string]$IntegrationTestFile,
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$PlaywrightArguments = @()
)

$ErrorActionPreference = 'Stop'

# All host Git operations use a fixed signed binary and a deliberately empty
# inherited Git configuration. Candidate .git/config may define executable
# fsmonitor, filter.clean, diff.external and hooks. None is a trustworthy
# instruction for a local CI snapshot.
$script:pinnedGit = 'C:\Program Files\Git\cmd\git.exe'
if (-not (Test-Path -LiteralPath $script:pinnedGit -PathType Leaf)) {
  throw 'The pinned Git for Windows executable is missing.'
}
$gitSignature = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $script:pinnedGit
if ($gitSignature.Status -ne 'Valid' -or -not $gitSignature.SignerCertificate -or
    -not $gitSignature.SignerCertificate.Subject.StartsWith('CN=Johannes Schindelin,', [System.StringComparison]::OrdinalIgnoreCase)) {
  throw 'Git for Windows Authenticode identity is unverified.'
}
foreach ($entry in @(Get-ChildItem Env: | Where-Object { $_.Name.StartsWith('GIT_', [System.StringComparison]::OrdinalIgnoreCase) })) {
  Remove-Item -LiteralPath ('Env:' + $entry.Name)
}
$env:GIT_CONFIG_NOSYSTEM = '1'
$env:GIT_CONFIG_GLOBAL = 'NUL'
$env:GIT_NO_REPLACE_OBJECTS = '1'
$env:GIT_ATTR_NOSYSTEM = '1'
function Invoke-PinnedGit { & $script:pinnedGit -c core.fsmonitor=false -c core.hooksPath=NUL @args }
$script:pinnedCleanRunner = $env:VIRKI_OFFLINE_PINNED_CLEAN_RUNNER -ceq '1'

function Read-VerifiedGitObjectBytes {
  param([string]$SourceRoot, [string]$Type, [string]$ObjectId)
  if ($Type -cnotin @('commit', 'tree', 'blob') -or $ObjectId -cnotmatch '^[a-f0-9]{40}$') {
    throw 'Invalid trusted Git object identity.'
  }
  # Git's local loose-object filename is NOT an authority. A same-account
  # attacker can temporarily replace even the commit object under its original
  # SHA filename and restore it before the Node postcheck. Authenticate every
  # object's actual framed bytes, including commit and intermediate trees,
  # before following any of its references to a PostgreSQL script.
  # Read raw stdout: Windows PowerShell 5.1 native pipelines corrupt binary
  # tree records and can re-encode UTF-8 or newline bytes.
  $start = [System.Diagnostics.ProcessStartInfo]::new()
  $start.FileName = $script:pinnedGit
  $start.WorkingDirectory = $SourceRoot
  $start.Arguments = '-C "' + $SourceRoot + '" -c core.fsmonitor=false cat-file ' + $Type + ' ' + $ObjectId
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start.RedirectStandardOutput = $true
  $start.RedirectStandardError = $true
  $process = [System.Diagnostics.Process]::Start($start)
  $memory = [System.IO.MemoryStream]::new()
  try {
    $chunk = [byte[]]::new(65536)
    while (($received = $process.StandardOutput.BaseStream.Read($chunk, 0, $chunk.Length)) -gt 0) {
      if ($memory.Length + $received -gt 1024 * 1024) {
        $process.Kill()
        throw 'Trusted Git object exceeds its fixed limit.'
      }
      $memory.Write($chunk, 0, $received)
    }
    if (-not $process.WaitForExit(30000) -or $process.ExitCode -ne 0) {
      throw 'Pinned Git object extraction failed.'
    }
    $bytes = $memory.ToArray()
    if ($bytes.Length -gt 1024 * 1024) { throw 'Trusted Git object exceeds its fixed limit.' }
    $header = [System.Text.Encoding]::ASCII.GetBytes($Type + ' ' + $bytes.Length + [char]0)
    $framed = [byte[]]::new($header.Length + $bytes.Length)
    [System.Buffer]::BlockCopy($header, 0, $framed, 0, $header.Length)
    [System.Buffer]::BlockCopy($bytes, 0, $framed, $header.Length, $bytes.Length)
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try { $observedOid = [System.BitConverter]::ToString($sha1.ComputeHash($framed)).Replace('-', '').ToLowerInvariant() }
    finally { $sha1.Dispose() }
    if ($observedOid -cne $ObjectId) { throw 'Trusted Git object content fails its independently computed framed SHA-1.' }
    return $bytes
  } finally {
    $memory.Dispose()
    $process.Dispose()
  }
}

function Find-VerifiedGitTreeEntry {
  param([byte[]]$Tree, [string]$Name, [switch]$Directory)
  $result = $null
  for ($offset = 0; $offset -lt $Tree.Length;) {
    $space = [Array]::IndexOf($Tree, [byte]32, $offset)
    if ($space -lt $offset) { throw 'Malformed pinned Git tree mode.' }
    $nul = [Array]::IndexOf($Tree, [byte]0, $space + 1)
    if ($nul -le $space + 1 -or $nul + 20 -gt $Tree.Length) {
      throw 'Malformed pinned Git tree entry.'
    }
    $mode = [System.Text.Encoding]::ASCII.GetString($Tree, $offset, $space - $offset)
    $entryName = [System.Text.Encoding]::ASCII.GetString($Tree, $space + 1, $nul - $space - 1)
    if ($entryName -ceq $Name) {
      if ($null -ne $result) { throw 'Duplicate pinned Git tree entry.' }
      if ($Directory) {
        if ($mode -cne '40000') { throw 'Pinned Git directory has an unexpected mode.' }
      } elseif ($mode -cnotin @('100644', '100755')) {
        throw 'Pinned Git file is not a regular blob.'
      }
      $oidBytes = [byte[]]::new(20)
      [System.Buffer]::BlockCopy($Tree, $nul + 1, $oidBytes, 0, 20)
      $result = [System.BitConverter]::ToString($oidBytes).Replace('-', '').ToLowerInvariant()
    }
    $offset = $nul + 21
  }
  if ($null -eq $result) { throw 'Pinned Git tree does not contain the requested entry.' }
  return $result
}

function New-VerifiedCommittedGitBlob {
  param([string]$SourceRoot, [string]$ExpectedHead, [string]$RelativePath, [string]$Destination)
  if ($ExpectedHead -cnotmatch '^[a-f0-9]{40}$' -or
      $RelativePath -cnotmatch '^[A-Za-z0-9._/-]{1,240}$' -or
      $RelativePath.Contains('..') -or
      -not [System.IO.Path]::IsPathRooted($Destination)) {
    throw 'Invalid pinned Git blob extraction identity.'
  }
  $segments = $RelativePath.Split('/')
  if (@($segments | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' }).Count -gt 0) {
    throw 'Pinned Git blob path is not canonical.'
  }
  # A trusted SHA is meaningful only when the entire referenced object graph
  # was verified at the point of extraction. Never use `rev-parse HEAD:path`
  # against the original mutable object database: it trusts the directory
  # contents under a named loose commit object without rehashing that commit.
  $commit = Read-VerifiedGitObjectBytes -SourceRoot $SourceRoot -Type commit -ObjectId $ExpectedHead
  $firstLineEnd = [Array]::IndexOf($commit, [byte]10)
  if ($firstLineEnd -ne 45 -or
      [System.Text.Encoding]::ASCII.GetString($commit, 0, 5) -cne 'tree ' -or
      [System.Text.Encoding]::ASCII.GetString($commit, 5, 40) -cnotmatch '^[a-f0-9]{40}$') {
    throw 'Trusted commit has no canonical pinned tree header.'
  }
  $treeOid = [System.Text.Encoding]::ASCII.GetString($commit, 5, 40)
  for ($i = 0; $i -lt $segments.Length; $i++) {
    $treeBytes = Read-VerifiedGitObjectBytes -SourceRoot $SourceRoot -Type tree -ObjectId $treeOid
    $oid = Find-VerifiedGitTreeEntry -Tree $treeBytes -Name $segments[$i] -Directory:($i -lt $segments.Length - 1)
    if ($i -lt $segments.Length - 1) { $treeOid = $oid }
  }
  $bytes = Read-VerifiedGitObjectBytes -SourceRoot $SourceRoot -Type blob -ObjectId $oid
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $committedSha256 = [System.BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha256.Dispose() }
    [System.IO.File]::WriteAllBytes($Destination, $bytes)
    # The expected digest MUST be derived from the verified bytes in memory,
    # not from the writable output path an adversary could swap after WriteAllBytes.
    return $committedSha256
}

function New-IsolatedGitSnapshot {
  param([string]$SourceRoot, [string]$SourceBranch, [string]$ExpectedHead,
    [string]$SnapshotRoot, [string]$BundleFile, [string]$StagedPatchFile, [string]$WorkingPatchFile,
    [switch]$PinnedCleanRunner)
  if ($SourceBranch -notmatch '^(?!/)(?!.*(?:/\/|\.\.))[A-Za-z0-9._/-]{1,200}$' -or
      $ExpectedHead -cnotmatch '^[a-f0-9]{40}$') { throw 'Invalid Git source snapshot identity.' }
  $commonDir = (Invoke-PinnedGit -C $SourceRoot rev-parse --path-format=absolute --git-common-dir)
  if ($LASTEXITCODE -ne 0 -or @($commonDir).Count -ne 1) { throw 'Git common object store is not available.' }
  if (-not $PinnedCleanRunner) {
    $sourceIndex = (Invoke-PinnedGit -C $SourceRoot rev-parse --path-format=absolute --git-path index)
    if ($LASTEXITCODE -ne 0 -or @($sourceIndex).Count -ne 1) { throw 'Git index is not available.' }
  }
  $objects = [System.IO.Path]::GetFullPath((Join-Path ([string]$commonDir) 'objects'))
  if (-not (Test-Path -LiteralPath $objects -PathType Container) -or
      (-not $PinnedCleanRunner -and -not (Test-Path -LiteralPath ([string]$sourceIndex) -PathType Leaf))) {
    throw 'Git source object store or index is unavailable.'
  }
  $safeGit = Join-Path $SnapshotRoot 'safe-git'
  $safeObjects = Join-Path $safeGit 'objects'
  New-Item -ItemType Directory -Path (Join-Path $safeObjects 'info') -Force -ErrorAction Stop | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $safeGit 'refs/heads') -Force -ErrorAction Stop | Out-Null
  $safeConfigPath = Join-Path $safeGit 'config'
  $safeConfigContents = "[core]`nrepositoryformatversion = 0`nbare = false`nfsmonitor = false`n"
  [System.IO.File]::WriteAllText($safeConfigPath, $safeConfigContents, [System.Text.UTF8Encoding]::new($false))
  [System.IO.File]::WriteAllText((Join-Path $safeGit 'HEAD'), "ref: refs/heads/$SourceBranch`n", [System.Text.UTF8Encoding]::new($false))
  $headRef = Join-Path $safeGit ('refs/heads/' + $SourceBranch)
  New-Item -ItemType Directory -Path (Split-Path -Parent $headRef) -Force -ErrorAction Stop | Out-Null
  [System.IO.File]::WriteAllText($headRef, "$ExpectedHead`n", [System.Text.UTF8Encoding]::new($false))
  # Preserve original --all semantics (branches, remote refs and tags), while
  # refusing refs/replace: those can rebind a trusted SHA when the resulting
  # bundle is cloned on Linux, where the host's Git environment is absent.
  $sourceRefs = @(Invoke-PinnedGit -C $SourceRoot show-ref)
  if ($LASTEXITCODE -ne 0 -or $sourceRefs.Count -gt 2048) { throw 'Git references cannot be safely inventoried.' }
  $seenRefNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  $safeRefFiles = [System.Collections.Generic.List[string]]::new()
  $safeRefNames = [System.Collections.Generic.List[string]]::new()
  $matchedBranch = $false
  foreach ($entry in $sourceRefs) {
    if (-not ($entry -cmatch '^([a-f0-9]{40}) (refs/[A-Za-z0-9._/-]{1,235})$')) {
      throw 'Malformed Git reference in source inventory.'
    }
    $referenceHash = $Matches[1]
    $referenceName = $Matches[2]
    if ($referenceName -match '(?:\.\.|//|(?:^|/)\.|\.lock(?:/|$))' -or
        $referenceName.EndsWith('/') -or -not $seenRefNames.Add($referenceName)) {
      throw 'Unsafe or ambiguous Git reference in source inventory.'
    }
    if ($referenceName -ceq ('refs/heads/' + $SourceBranch)) {
      if ($referenceHash -cne $ExpectedHead) { throw 'Source branch SHA changed before Git snapshot.' }
      $matchedBranch = $true
    }
    if ($referenceName.StartsWith('refs/replace/', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
    # The clean runner exports ONLY the verified HEAD. Other same-account
    # refs and any dirty index/working-tree file must never cross this gate.
    if ($PinnedCleanRunner -and $referenceName -cne ('refs/heads/' + $SourceBranch)) { continue }
    $safeRefPath = Join-Path $safeGit $referenceName
    New-Item -ItemType Directory -Path (Split-Path -Parent $safeRefPath) -Force -ErrorAction Stop | Out-Null
    [System.IO.File]::WriteAllText($safeRefPath, "$referenceHash`n", [System.Text.UTF8Encoding]::new($false))
    $safeRefFiles.Add($safeRefPath)
    $safeRefNames.Add($referenceName)
  }
  if (-not $matchedBranch) { throw 'Original source branch reference is not present.' }
  [System.IO.File]::WriteAllText((Join-Path $safeObjects 'info/alternates'), "$objects`n", [System.Text.UTF8Encoding]::new($false))
  if (-not $PinnedCleanRunner) {
    $safeIndexPath = Join-Path $safeGit 'index'
    $sourceIndexBytes = [System.IO.File]::ReadAllBytes([string]$sourceIndex)
    [System.IO.File]::WriteAllBytes($safeIndexPath, $sourceIndexBytes)
  }
  $safeArgs = @(('--git-dir=' + $safeGit), ('--work-tree=' + $SourceRoot), '-c', 'core.fsmonitor=false')
  # Windows kernel sharing locks block writes, replacement and rename by a
  # concurrent same-account process while Git consumes this exact configuration
  # and index. Open all files read-only with FileShare.Read, then recheck the
  # config under those locks before launching ANY Git command.
  $pinnedFiles = @($safeConfigPath, (Join-Path $safeGit 'HEAD'),
    (Join-Path $safeObjects 'info/alternates')) + $safeRefFiles.ToArray()
  if (-not $PinnedCleanRunner) { $pinnedFiles += $safeIndexPath }
  $locks = [System.Collections.Generic.List[System.IDisposable]]::new()
  try {
    foreach ($filename in $pinnedFiles) {
      $locks.Add([System.IO.FileStream]::new($filename, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read))
    }
    if ([System.IO.File]::ReadAllText($safeConfigPath) -cne $safeConfigContents) {
      throw 'Isolated Git config changed before its kernel pin was established.'
    }
    if (-not $PinnedCleanRunner -and -not [System.Collections.StructuralComparisons]::StructuralEqualityComparer.Equals(
        $sourceIndexBytes, [System.IO.File]::ReadAllBytes($safeIndexPath))) {
      throw 'Isolated Git index changed before its kernel pin was established.'
    }
    # Enumerate only the originally pinned references, not `--all`, so a new
    # attacker-added refs/replace path cannot enter the temporary bundle.
    & $script:pinnedGit @safeArgs bundle create $BundleFile @($safeRefNames.ToArray())
    if ($LASTEXITCODE -ne 0) { throw 'Could not create safe Git bundle.' }
    if ($PinnedCleanRunner) {
      # NEVER read index, tracked checkout bytes, Git diff or untracked files
      # after the Node clean gate. A transient edit could otherwise be packaged
      # while the Node before/after source probes both report CLEAN.
      [System.IO.File]::WriteAllBytes($StagedPatchFile, [byte[]]@())
      [System.IO.File]::WriteAllBytes($WorkingPatchFile, [byte[]]@())
      return @()
    }
    & $script:pinnedGit @safeArgs diff --no-ext-diff --no-textconv --cached --binary ('--output=' + $StagedPatchFile)
    if ($LASTEXITCODE -ne 0) { throw 'Could not create safe staged Git patch.' }
    & $script:pinnedGit @safeArgs diff --no-ext-diff --no-textconv --binary ('--output=' + $WorkingPatchFile)
    if ($LASTEXITCODE -ne 0) { throw 'Could not create safe working Git patch.' }
    $foundUntracked = @(& $script:pinnedGit @safeArgs ls-files --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) { throw 'Could not inventory Git untracked files.' }
    return $foundUntracked
  } finally {
    foreach ($handle in $locks) { $handle.Dispose() }
  }
}

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
$repositoryBranch = (Invoke-PinnedGit -C $repoRoot branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or $repositoryBranch -notmatch '^[A-Za-z0-9._/-]{1,240}$') {
  throw 'The isolated Docker snapshot requires a named local branch with a supported ref name.'
}
$runId = [Guid]::NewGuid().ToString('N')
$evidenceRoot = Join-Path $repoRoot '.virki-mission-tmp/isolated-runs'
$runEvidenceDirectory = Join-Path $evidenceRoot $runId
$evidenceIgnore = (Invoke-PinnedGit -C $repoRoot check-ignore --quiet '.virki-mission-tmp/isolated-runs')
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
  integrationMigrator = & $databaseUrl 'virki_migrator' $passwords.migrator '127.0.0.1'
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
$script:bootstrapVirginExitCode = $null
$script:runnerName = $runnerName
$sourceHead = (Invoke-PinnedGit -C $repoRoot rev-parse HEAD).Trim()
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
  param([string]$Name, [string[]]$Command, [string[]]$Environment = @(), [string]$EvidenceLogPath, [switch]$Preparatory)
  Write-Output "`n[$Name]"
  $startedAt = [DateTimeOffset]::UtcNow
  $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
  if ($EvidenceLogPath) {
    # GNU timeout runs INSIDE the pinned disposable Linux container. Combined
    # with the outer supervisor's total deadline, a stuck stage cannot claim
    # completion or remain in a successful release evidence manifest.
    $stageOutput = @(Invoke-PinnedDocker exec --workdir /workspace @Environment $script:runnerName timeout --kill-after=10s 1800s @Command 2>&1)
    $exitCode = $LASTEXITCODE
    $stageLines = [string[]]@($stageOutput | ForEach-Object { $_.ToString() })
    [System.IO.File]::WriteAllLines($EvidenceLogPath, $stageLines, [System.Text.UTF8Encoding]::new($false))
    foreach ($line in $stageLines) { Write-Output $line }
  } else {
    Invoke-PinnedDocker exec --workdir /workspace @Environment $script:runnerName timeout --kill-after=10s 1800s @Command
    $exitCode = $LASTEXITCODE
  }
  $stopwatch.Stop()
  $finishedAt = [DateTimeOffset]::UtcNow
  if ($Preparatory) {
    # This independent virgin-database preflight is mandatory for integration
    # and belongs to the integration gate. Preserve its separate raw log and
    # status, but keep the release manifest's 19 named gates unchanged.
    if ($Name -ne 'bootstrap-virgin-tests') { throw 'Unrecognized preparatory stage.' }
    $script:bootstrapVirginExitCode = $exitCode
  } else {
    $script:results.Add($Name + '=' + $exitCode)
    $script:stageManifest.Add([ordered]@{
      name = $Name
      startedUtc = $startedAt.ToString('o')
      finishedUtc = $finishedAt.ToString('o')
      durationMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3)
      exitCode = $exitCode
    })
  }
  $durationInvariant = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 3).ToString('0.###', [System.Globalization.CultureInfo]::InvariantCulture)
  Write-Output ("[RESULT] {0} exit={1} durationMs={2}" -f $Name, $exitCode, $durationInvariant)
  if ($Preparatory -and $exitCode -ne 0) { throw 'Virgin database integration preflight failed.' }
}

function Invoke-LoggedStage {
  param([string]$Name, [string]$LogName, [string]$CommandText, [string[]]$Environment = @(), [string]$EvidenceLogPath, [switch]$CaptureFullOutput, [switch]$Preparatory)
  $logOutputCommand = if ($CaptureFullOutput) { 'cat' } else { 'tail -n 80' }
  # Group the ENTIRE stage before redirection. Without parentheses, A && B
  # sends only B to the log, so an A failure leaves no file and tail masks
  # the actual error. Preserve the true compound command exit status.
  $shellCommand = '( ' + $CommandText + ' ) > /tmp/' + $LogName + '.log 2>&1; status=$?; ' + $logOutputCommand + ' /tmp/' + $LogName + '.log; exit $status'
  Invoke-Stage -Name $Name -Command @('bash', '-lc', $shellCommand) -Environment $Environment -EvidenceLogPath $EvidenceLogPath -Preparatory:$Preparatory
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
  $untrackedFiles = @(New-IsolatedGitSnapshot -SourceRoot $repoRoot -SourceBranch $repositoryBranch -ExpectedHead $sourceHead -SnapshotRoot $snapshotDirectory -BundleFile $bundlePath -StagedPatchFile $stagedPatchPath -WorkingPatchFile $workingPatchPath -PinnedCleanRunner:$script:pinnedCleanRunner)
  if ($script:pinnedCleanRunner) {
    # Known SHA-256 of an empty byte string, NOT a mutable path's observed hash.
    # Even if someone races a patch file before docker cp, the Docker-side
    # verified bytes must be exactly empty before any attempt to apply them.
    $script:stagedPatchSha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    $script:workingTreePatchSha256 = $script:stagedPatchSha256
    if ($untrackedFiles.Count -ne 0) { throw 'Pinned clean runner must never import untracked source.' }
  } else {
    $script:stagedPatchSha256 = Get-FileSha256 -LiteralPath $stagedPatchPath
    $script:workingTreePatchSha256 = Get-FileSha256 -LiteralPath $workingPatchPath
  }
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

  foreach ($initFile in @(
      @{ Relative = 'infra/postgres-init/10-virki-database-roles.sh'; Name = '10-virki-database-roles.sh' },
      @{ Relative = 'scripts/e2e/20-virki-e2e-runtime-test-role.sh'; Name = '20-virki-e2e-runtime-test-role.sh' })) {
    $sourceInitPath = Join-Path $repoRoot $initFile.Relative
    $expectedInitSha256 = $null
    if ($script:pinnedCleanRunner) {
      # No direct checkout read/copy may cross the clean gate, including the
      # PostgreSQL shell scripts run automatically on first container start.
      $sourceInitPath = Join-Path $snapshotDirectory $initFile.Name
      $expectedInitSha256 = New-VerifiedCommittedGitBlob -SourceRoot $repoRoot -ExpectedHead $sourceHead -RelativePath $initFile.Relative -Destination $sourceInitPath
    }
    $pinnedInitHandle = $null
    try {
      if ($script:pinnedCleanRunner) {
        $pinnedInitHandle = [System.IO.FileStream]::new($sourceInitPath, [System.IO.FileMode]::Open,
          [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        if ((Get-FileSha256 -LiteralPath $sourceInitPath) -cne $expectedInitSha256) {
          throw 'Committed PostgreSQL initialization source changed before its file pin.'
        }
      }
      $containerInitPath = '/docker-entrypoint-initdb.d/' + $initFile.Name
      Invoke-PinnedDocker cp $sourceInitPath ($databaseName + ':' + $containerInitPath) | Out-Null
      if ($LASTEXITCODE -ne 0) { throw 'Could not copy a database role initializer.' }
      if ($script:pinnedCleanRunner) {
        # Round-trip verify the stopped container's exact init script BEFORE
        # `docker start` can execute it. Its custody is held by the daemon.
        $returnedInitPath = Join-Path $snapshotDirectory ('verified-' + $initFile.Name)
        Invoke-PinnedDocker cp ($databaseName + ':' + $containerInitPath) $returnedInitPath | Out-Null
        if ($LASTEXITCODE -ne 0 -or (Get-FileSha256 -LiteralPath $returnedInitPath) -cne $expectedInitSha256) {
          throw 'Database role initializer changed across Docker copy boundary.'
        }
      }
    } finally {
      if ($null -ne $pinnedInitHandle) { $pinnedInitHandle.Dispose() }
    }
  }
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
  if ($script:pinnedCleanRunner) {
    # Verify the *consumed* immutable Git objects and materialized checkout
    # inside the runner before any repo-supplied package/script can execute.
    # This must happen after Docker copy+clone, not merely at host preflight.
    Invoke-PinnedDocker exec --workdir /workspace $runnerName bash -lc 'set -eu; test ! -s /tmp/staged.patch; test ! -s /tmp/working-tree.patch; git -c core.fsmonitor=false fsck --full --strict --no-reflogs >/dev/null; test -z "$(git -c core.fsmonitor=false status --porcelain --untracked-files=all)"; git -c core.fsmonitor=false diff --no-ext-diff --no-textconv --exit-code; git -c core.fsmonitor=false diff --cached --no-ext-diff --no-textconv --exit-code'
    if ($LASTEXITCODE -ne 0) { throw 'Pinned clean source objects or checkout failed runtime integrity verification.' }
  }
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
    Invoke-LoggedStage -Name 'bootstrap-virgin-tests' -LogName 'bootstrap-virgin-tests' -CommandText 'npm run test:integration -- packages/auth/src/bootstrap-first-admin.integration.test.ts' -Environment $virginBootstrapEnvironment -EvidenceLogPath $bootstrapVirginTestsEvidencePath -CaptureFullOutput -Preparatory
    $integrationEnvironment = @('--env', ('DATABASE_URL=' + $urls.runtime), '--env', ('MIGRATION_DATABASE_URL=' + $urls.integrationMigrator), '--env', ('VIRKI_INTEGRATION_DATABASE_URL=' + $urls.integration), '--env', 'VIRKI_CORE_TEST_DATABASE_CONFIRM=disposable')
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
    if ($env:VIRKI_E2E_PASSKEYS -eq 'true') { $e2eEnvironment += @('--env', 'VIRKI_E2E_PASSKEYS=true') }
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
      bootstrapVirginTestsLog = if (Test-Path -LiteralPath $bootstrapVirginTestsEvidencePath) { [System.IO.Path]::GetFileName($bootstrapVirginTestsEvidencePath) } else { $null }
      bootstrapVirginTestsExitCode = $script:bootstrapVirginExitCode
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
