// Local smoke-test cleanup. This is an ownership safety check, not a Docker
// security boundary against another process with equivalent daemon access.
const RESOURCE_NAME = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,180}$/u;
const DOCKER_ID = /^[a-f0-9]{64}$/u;
const OWNER_LABEL = "org.virki.validation";

function refuse() {
  throw new Error("Disposable Docker cleanup refused: ownership, inspection or removal could not be confirmed.");
}

function dockerMissing(result, kind, target) {
  if (result?.error || result?.status === 0 || typeof result?.stderr !== "string") return false;
  const last = result.stderr.trim().split(/\r?\n/u).at(-1);
  return [
    `Error: No such object: ${target}`,
    `Error response from daemon: No such container: ${target}`,
    `Error response from daemon: No such object: ${target}`,
    ...(kind === "network" ? [`Error response from daemon: network ${target} not found`] : []),
  ].includes(last);
}

function inspectedObject(result, kind, expectedName, owner) {
  if (result.error || result.status !== 0 || typeof result.stdout !== "string") refuse();
  let records;
  try { records = JSON.parse(result.stdout); } catch { refuse(); }
  if (!Array.isArray(records) || records.length !== 1) refuse();
  const entry = records[0];
  const observedName = kind === "container" ? `/${expectedName}` : expectedName;
  const labels = kind === "container" ? entry?.Config?.Labels : entry?.Labels;
  if (entry?.Name !== observedName || !DOCKER_ID.test(entry?.Id ?? "") ||
      !labels || labels[OWNER_LABEL] !== owner) refuse();
  return entry.Id;
}

export function cleanupOwnedDockerResources({ invoke, owner, containers, network }) {
  if (typeof invoke !== "function" || !RESOURCE_NAME.test(owner ?? "") ||
      !Array.isArray(containers) || containers.some((name) => !RESOURCE_NAME.test(name)) ||
      new Set(containers).size !== containers.length || !RESOURCE_NAME.test(network ?? "") ||
      containers.includes(network)) refuse();

  const resources = [
    ...containers.map((name) => ({ kind: "container", name })),
    { kind: "network", name: network },
  ];
  const owned = [];
  // Preflight every object before deleting anything; never cleanup on names alone.
  for (const { kind, name } of resources) {
    const inspected = invoke([kind, "inspect", name]);
    if (dockerMissing(inspected, kind, name)) continue;
    owned.push({ kind, id: inspectedObject(inspected, kind, name, owner) });
  }
  for (const { kind, id } of owned) {
    const args = kind === "container"
      ? ["container", "rm", "--force", "--volumes", id]
      : ["network", "rm", id];
    const result = invoke(args);
    if (result?.error || result?.status !== 0) refuse();
    const checked = invoke([kind, "inspect", id]);
    if (!dockerMissing(checked, kind, id)) refuse();
  }
}
