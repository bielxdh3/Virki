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
foreach ($name in @('Invoke-DockerObservation', 'Write-DockerMutationJournal', 'Assert-OwnedDockerIdentity',
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
