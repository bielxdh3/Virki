import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const path = resolve(dirname(fileURLToPath(import.meta.url)), "run-isolated-linux-docker.ps1");

function runPowerShellDockerMock(caseScript) {
  // AST extraction defines only the pure owner helpers. The launcher (and
  // therefore the real Docker preflight or any Docker daemon) never runs.
  const source = String.raw`
$ErrorActionPreference = 'Stop'
$scriptPath = '${path.replaceAll("'", "''")}'
$parsed = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$null)
foreach ($name in @('Invoke-PinnedDocker', 'Invoke-DockerObservation', 'Write-DockerMutationJournal', 'Assert-OwnedDockerIdentity',
                    'Invoke-CreateOwnedDockerResource', 'Invoke-OwnedDockerCleanup')) {
  $functionAst = $parsed.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
  }, $true) | Select-Object -First 1
  if (-not $functionAst) { throw "missing reviewed function $name" }
  Invoke-Expression $functionAst.Extent.Text
}
$runId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$script:dockerMutationJournalPath = Join-Path $env:TEMP ('virki-owner-mock-' + [Guid]::NewGuid().ToString('N') + '.jsonl')
$script:dockerOwnerLabel = 'org.virki.e2e.owner=' + $runId
$script:dockerMutationUncertain = $false
$script:ownedResources = @{ runner = $false }
$script:ownedDockerIds = @{ runner = $null }
$script:dockerResourceNames = @{ runner = 'virki-e2e-runner-owned' }
$script:removed = $false
$script:removeTargets = @()
try {
${caseScript}
} finally {
  if (Test-Path -LiteralPath $script:dockerMutationJournalPath) {
    Remove-Item -LiteralPath $script:dockerMutationJournalPath -Force
  }
}
`;
  const encoded = Buffer.from(source, "utf16le").toString("base64");
  return spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive",
    "-EncodedCommand", encoded], { encoding: "utf8", timeout: 15_000 });
}

test("PowerShell mock: foreign Docker label never reaches container removal", {
  skip: process.platform !== "win32" && "Windows PowerShell security fixture",
}, () => {
  const result = runPowerShellDockerMock(String.raw`
$script:ownedResources.runner = $true
$script:ownedDockerIds.runner = ('a' * 64)
function Invoke-PinnedDocker {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$DockerArguments)
  if ($DockerArguments[0] -eq 'container' -and $DockerArguments[1] -eq 'inspect') {
    $global:LASTEXITCODE = 0
    return (ConvertTo-Json -InputObject @(@{
      Id = ('a' * 64); Name = '/virki-e2e-runner-owned'
      Config = @{ Labels = @{ 'org.virki.e2e.owner' = 'foreign-owner' } }
    }) -Depth 5)
  }
  throw 'Unapproved foreign resource mutation was invoked'
}
try {
  Invoke-OwnedDockerCleanup 'runner'
  throw 'Foreign resource cleanup was erroneously accepted'
} catch {
  if ($_.Exception.Message -notmatch 'owner/name verification') { throw }
  'FOREIGN_RESOURCE_BLOCKED'
}
`);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /FOREIGN_RESOURCE_BLOCKED/u);
});

test("PowerShell mock: pinned Docker CLI passes Node -e and Docker --env flags verbatim", {
  skip: process.platform !== "win32" && "Windows PowerShell 5.1 argument binding fixture",
}, () => {
  const result = runPowerShellDockerMock(String.raw`
$script:dockerHost = 'npipe:////./pipe/dockerDesktopLinuxEngine'
$script:dockerCli = 'Mock-VerifiedNativeDocker'
function Mock-VerifiedNativeDocker {
  $script:forwardedDockerArgs = @($args)
  $global:LASTEXITCODE = 0
  'mock-pass'
}
$out = Invoke-PinnedDocker exec --workdir /workspace --env 'TEST=local' 'owned-runner' node -e 'process.exit(0)'
$expected = @('--host', $script:dockerHost, 'exec', '--workdir', '/workspace', '--env', 'TEST=local',
  'owned-runner', 'node', '-e', 'process.exit(0)')
if (($script:forwardedDockerArgs -join '|') -cne ($expected -join '|') -or $out -cne 'mock-pass') {
  throw 'Pinned Docker arguments or Node -e were modified by PowerShell parameter binding'
}
'NODE_E_PASSTHROUGH_VERIFIED'
`);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /NODE_E_PASSTHROUGH_VERIFIED/u);
});

test("PowerShell mock: lost Docker create ACK persists an unresolved intent", {
  skip: process.platform !== "win32" && "Windows PowerShell security fixture",
}, () => {
  const result = runPowerShellDockerMock(String.raw`
function Invoke-PinnedDocker {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$DockerArguments)
  $global:LASTEXITCODE = 1
  return ''
}
try {
  $null = Invoke-CreateOwnedDockerResource 'runner' 'virki-e2e-runner-owned' @('create', '--name', 'virki-e2e-runner-owned')
  throw 'Lost ACK was incorrectly accepted'
} catch {
  if ($_.Exception.Message -notmatch 'creation ACK is uncertain') { throw }
}
$states = @(Get-Content -LiteralPath $script:dockerMutationJournalPath |
  ForEach-Object { ($_ | ConvertFrom-Json).state })
if (($states -join ',') -cne 'MUTATION_PENDING,RECONCILIATION_REQUIRED') { throw 'Missing durable pending/uncertain journal' }
if ($script:ownedResources.runner -or -not $script:dockerMutationUncertain) { throw 'Uncertain ACK falsely owns Docker resource' }
'LOST_ACK_PRESERVED'
`);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /LOST_ACK_PRESERVED/u);
});

test("PowerShell mock: owned container removal uses exact verified Docker ID", {
  skip: process.platform !== "win32" && "Windows PowerShell security fixture",
}, () => {
  const result = runPowerShellDockerMock(String.raw`
function Invoke-PinnedDocker {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$DockerArguments)
  if ($DockerArguments[0] -eq 'create') {
    $global:LASTEXITCODE = 0
    return ('a' * 64)
  }
  if ($DockerArguments[0] -eq 'container' -and $DockerArguments[1] -eq 'inspect') {
    if ($script:removed) {
      $global:LASTEXITCODE = 1
      return ('Error: No such object: ' + ('a' * 64))
    }
    $global:LASTEXITCODE = 0
    return (ConvertTo-Json -InputObject @(@{
      Id = ('a' * 64); Name = '/virki-e2e-runner-owned'
      Config = @{ Labels = @{ 'org.virki.e2e.owner' = $runId } }
    }) -Depth 5)
  }
  if ($DockerArguments[0] -eq 'container' -and $DockerArguments[1] -eq 'rm') {
    $script:removeTargets += @($DockerArguments[-1])
    $script:removed = $true
    $global:LASTEXITCODE = 0
    return ('a' * 64)
  }
  throw ('Unexpected Docker mock verb: ' + ($DockerArguments -join ' '))
}
$id = Invoke-CreateOwnedDockerResource 'runner' 'virki-e2e-runner-owned' @('create', '--name', 'virki-e2e-runner-owned')
Invoke-OwnedDockerCleanup 'runner'
if (-not $script:removed -or $script:removeTargets.Count -ne 1 -or
    $script:removeTargets[0] -cne ('a' * 64) -or $script:ownedResources.runner) {
  throw 'Cleanup did not exclusively remove the verified immutable ID'
}
$states = @(Get-Content -LiteralPath $script:dockerMutationJournalPath |
  ForEach-Object { ($_ | ConvertFrom-Json).state })
if (($states -join ',') -cne 'MUTATION_PENDING,MUTATION_ACKNOWLEDGED,REMOVE_PENDING,REMOVE_CONFIRMED') {
  throw 'Durable cleanup state transitions do not match confirmed Docker events'
}
'OWNER_ID_CLEANUP_VERIFIED'
`);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /OWNER_ID_CLEANUP_VERIFIED/u);
});

test("PowerShell mock: browser anonymous volume can only be removed with its owner seed ID", {
  skip: process.platform !== "win32" && "Windows PowerShell security fixture",
}, () => {
  const result = runPowerShellDockerMock(String.raw`
$script:ownedResources.browserSeed = $true
$script:ownedDockerIds.browserSeed = ('a' * 64)
$script:dockerResourceNames.browserSeed = 'virki-e2e-browser-seed-owned'
$script:browserAnonymousVolume = ('b' * 64)
function Invoke-PinnedDocker {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$DockerArguments)
  if ($DockerArguments[0] -eq 'container' -and $DockerArguments[1] -eq 'inspect') {
    if ($script:removed) {
      $global:LASTEXITCODE = 1
      return ('Error: No such object: ' + ('a' * 64))
    }
    $global:LASTEXITCODE = 0
    return (ConvertTo-Json -InputObject @(@{
      Id = ('a' * 64); Name = '/virki-e2e-browser-seed-owned'
      Config = @{ Labels = @{ 'org.virki.e2e.owner' = $runId } }
    }) -Depth 5)
  }
  if ($DockerArguments[0] -eq 'container' -and $DockerArguments[1] -eq 'rm') {
    if (($DockerArguments -join ',') -cne ('container,rm,--force,--volumes,' + ('a' * 64))) {
      throw 'Removal did not identify only the owned immutable browser seed'
    }
    $script:removed = $true
    $global:LASTEXITCODE = 0
    return ('a' * 64)
  }
  if ($DockerArguments[0] -eq 'volume' -and $DockerArguments[1] -eq 'inspect') {
    if (-not $script:removed -or $DockerArguments[2] -cne ('b' * 64)) {
      throw 'Unexpected volume observation'
    }
    $global:LASTEXITCODE = 1
    return ('Error: No such volume: ' + ('b' * 64))
  }
  throw ('Unexpected Docker operation (foreign mutable volume deletion?): ' + ($DockerArguments -join ' '))
}
Invoke-OwnedDockerCleanup 'browserSeed'
if (-not $script:removed -or $script:ownedResources.browserSeed -or $script:dockerMutationUncertain) {
  throw 'Browser seed cleanup was not owner-confirmed'
}
$states = @(Get-Content -LiteralPath $script:dockerMutationJournalPath |
  ForEach-Object { ($_ | ConvertFrom-Json).state })
if (($states -join ',') -cne 'REMOVE_PENDING,REMOVE_CONFIRMED') {
  throw 'Anonymous volume cleanup journal missing'
}
'ANONYMOUS_VOLUME_OWNED_BY_SEED'
`);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /ANONYMOUS_VOLUME_OWNED_BY_SEED/u);
});

test("PowerShell mock: Docker Desktop network removal accepts only exact-ID missing diagnostics", {
  skip: process.platform !== "win32" && "Windows PowerShell 5.1 Docker network fixture",
}, () => {
  const result = runPowerShellDockerMock(String.raw`
$script:ownedResources.network = $true
$script:ownedDockerIds.network = ('b' * 64)
$script:dockerResourceNames.network = 'virki-e2e-own-network'
function Invoke-PinnedDocker {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$DockerArguments)
  if ($DockerArguments[0] -eq 'network' -and $DockerArguments[1] -eq 'inspect') {
    if (-not $script:removed) {
      $global:LASTEXITCODE = 0
      return (ConvertTo-Json -InputObject @(@{
        Id = ('b' * 64); Name = 'virki-e2e-own-network'
        Labels = @{ 'org.virki.e2e.owner' = $runId }
      }) -Depth 5)
    }
    $global:LASTEXITCODE = 1
    return @('[]', ('Error response from daemon: network ' + ('b' * 64) + ' not found'))
  }
  if ($DockerArguments[0] -eq 'network' -and $DockerArguments[1] -eq 'rm') {
    if ($DockerArguments[2] -cne ('b' * 64)) { throw 'Not the immutable network ID' }
    $script:removed = $true
    $global:LASTEXITCODE = 0
    return ('b' * 64)
  }
  throw 'Unexpected mutation or observation'
}
Invoke-OwnedDockerCleanup 'network'
if ($script:ownedResources.network -or $script:dockerMutationUncertain -or -not $script:removed) {
  throw 'Exact-ID network removal was not confirmed'
}
'NETWORK_IMMUTABLE_ID_ABSENCE_VERIFIED'
`);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /NETWORK_IMMUTABLE_ID_ABSENCE_VERIFIED/u);
});
