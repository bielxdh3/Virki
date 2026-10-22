import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { lstatSync, realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { runProtectedWindowsJournalOperation, verifyTrustedWindowsDockerCli, LOCAL_ENGINE } from "../../infra/offline/disposable-local-docker.mjs";

const DOCKER_EXE = "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe";
const ID = /^[a-f0-9]{64}$/u;
const RUN_LABEL = "virki.role-test.run";
const FIXTURE_LABEL = "virki.role-test.fixture";
const KIND_LABEL = "virki.role-test.kind";
const POSTGRES = "postgres:17@sha256:2d2b8998d31037bf721cfdf764d76ba74171b4fab3431b7f72c27c56ddbdf9e3";
// Docker Desktop's plugin actually executed by docker.exe on this Windows host.
// Verify this exact installation path rather than a different signed copy in
// resources/cli-plugins (which Docker's plugin search does not select here).
const BUILDX = "C:\\Program Files\\Docker\\cli-plugins\\docker-buildx.exe";
const POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const SECRET_ENV = /^(?:POSTGRES_(?:PASSWORD|DB|USER|HOST_AUTH_METHOD|INITDB_ARGS)|VIRKI_(?:RUNTIME_DB_PASSWORD|MIGRATOR_DB_PASSWORD|AUDIT_MAINTENANCE_DB_PASSWORD|E2E_DATABASE_PASSWORD|TEST_MIGRATOR_PASSWORD)|(?:MIGRATION_)?DATABASE_URL|PGPASSWORD|AUDIT_LOG_RETENTION_DAYS)$/u;

export function requireRoleFixtureLocalEnvironment(env = process.env, platform = process.platform) {
  if (platform !== "win32" || Object.keys(env).some((key) =>
    /^(?:DOCKER_|COMPOSE_|NODE_OPTIONS$|NODE_EXTRA_CA_CERTS$|DATABASE_URL$|MIGRATION_DATABASE_URL$|PG(?:PASSWORD|HOST|PORT|SERVICE|PASSFILE|OPTIONS)$)/iu.test(key))) {
    throw new Error("Role fixture requires local Windows Docker Desktop and no Docker/Node/database overrides.");
  }
}

function safeEnvironment(extra) {
  if (Object.keys(extra).some((key) => !SECRET_ENV.test(key))) throw Error("Role fixture rejected an unexpected subprocess variable.");
  return {
    SystemRoot: "C:\\Windows", WINDIR: "C:\\Windows",
    PATH: "C:\\Windows\\System32;C:\\Windows",
    TEMP: "C:\\Windows\\Temp", TMP: "C:\\Windows\\Temp",
    USERPROFILE: os.homedir(),
    APPDATA: path.join(os.homedir(), "AppData", "Roaming"),
    LOCALAPPDATA: path.join(os.homedir(), "AppData", "Local"),
    ProgramFiles: "C:\\Program Files", ProgramData: "C:\\ProgramData",
    HOMEDRIVE: "C:", HOMEPATH: os.homedir().slice(2),
    ...extra,
  };
}

function argument(args, key) {
  const at = args.indexOf(key);
  return at >= 0 ? args[at + 1] : undefined;
}

function identicalArgs(actual, expected) {
  return actual.length === expected.length && expected.every((item, at) => actual[at] === item);
}

function expectedPostgresCreate(name, runId) {
  const interrupted = name.startsWith("virki-role-interrupted-");
  return [
    "create", "--name", name, "--network", `${name}-net`,
    "--network-alias", "postgres",
    "--label", `${RUN_LABEL}=${runId}`,
    "--label", `${FIXTURE_LABEL}=${name}`,
    "--label", `${KIND_LABEL}=postgres`,
    "--health-cmd", "pg_isready -h 127.0.0.1 -U virki_bootstrap -d virki_roles_test",
    "--health-interval", "1s", "--health-timeout", "3s", "--health-retries", "60",
    "--env", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
    "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
    "--env", "POSTGRES_DB=virki_roles_test",
    "--env", "POSTGRES_USER=virki_bootstrap",
    "--env=POSTGRES_PASSWORD",
    "--env=VIRKI_RUNTIME_DB_PASSWORD",
    "--env=VIRKI_MIGRATOR_DB_PASSWORD",
    "--env=VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD",
    "--env=AUDIT_LOG_RETENTION_DAYS",
    "--env=VIRKI_E2E_DATABASE_PASSWORD",
    ...(interrupted
      ? ["--mount", `type=volume,source=${name}-data,target=/var/lib/postgresql/data`]
      : ["--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=512m"]),
    POSTGRES,
  ];
}

function expectedMigrationRun(name, fixture, runId, imageTag, command, databaseKey, retention = false) {
  return [
    "run", "--name", name, "--network", `${fixture}-net`,
    "--label", `${RUN_LABEL}=${runId}`,
    "--label", `${FIXTURE_LABEL}=${fixture}`,
    "--label", `${KIND_LABEL}=migration-runner`,
    "--env", databaseKey,
    ...(retention ? ["--env", "AUDIT_LOG_RETENTION_DAYS"] : []),
    "--entrypoint", "node", imageTag, ...command,
  ];
}

const MIGRATOR_COMMANDS = [
  ["/app/packages/database/scripts/prisma-migrate.mjs", "deploy"],
  ["/app/packages/database/scripts/prisma-migrate.mjs", "status"],
  ["/app/node_modules/prisma/build/index.js", "migrate", "deploy",
    "--schema", "/app/packages/database/prisma/schema.prisma"],
];

export function verifyOfficialBuildx({ stat = lstatSync, canonicalize = realpathSync.native, authenticate = spawnSync } = {}) {
  try {
    const info = stat(BUILDX);
    if (!info.isFile() || info.isSymbolicLink() || canonicalize(BUILDX).toLowerCase() !== BUILDX.toLowerCase()) {
      throw Error("Buildx installation path is untrusted.");
    }
    const script = `$s=Get-AuthenticodeSignature -LiteralPath '${BUILDX}'; if ($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch '(^|, )O=Docker Inc(,|$)') { exit 1 }; [Console]::Out.Write('BUILDX_SIGNED')`;
    const result = authenticate(POWERSHELL, ["-NoProfile", "-NonInteractive", "-Command", script], {
      shell: false, windowsHide: true, timeout: 10_000, maxBuffer: 1024, encoding: "utf8", env: safeEnvironment({}),
    });
    if (result.error || result.status !== 0 || result.stdout !== "BUILDX_SIGNED") throw Error("Buildx publisher unverifiable.");
  } catch { throw Error("Role fixture requires the signed Docker Desktop Buildx plugin."); }
}

// No caller may use a mutable name as authority: each mutation and every
// container read operation is rebound to a previously observed immutable ID.
export class OwnedRoleDocker {
  constructor({ runId, cwd, invoke = spawnSync, journal = runProtectedWindowsJournalOperation,
    verify = verifyTrustedWindowsDockerCli, verifyBuildx = verifyOfficialBuildx,
    env = process.env, platform = process.platform }) {
    requireRoleFixtureLocalEnvironment(env, platform);
    if (!/^[a-f0-9]{24}$/u.test(runId)) throw Error("Invalid role fixture run ID.");
    this.invoke = invoke;
    this.binary = invoke === spawnSync ? verify() : DOCKER_EXE;
    if (invoke === spawnSync) verifyBuildx();
    this.cwd = cwd;
    this.runId = runId;
    this.journal = journal;
    this.owner = randomBytes(16).toString("hex");
    this.journalName = `virki-offline-fixture-${this.owner}`;
    this.directory = path.join(os.homedir(), ".virki", "offline-docker-reconciliation");
    this.evidence = path.join(this.directory, `${this.journalName}.jsonl`);
    this.records = new Map();
    this.networks = new Map();
    this.volumes = new Set();
    this.image = null;
    this.imageTag = null;
    this.uncertain = false;
    this.created = false;
    this.engineId = null;
    this.verifyEngine();
    this.writeJournal("create", { event: "run_reservation", runId, owner: this.owner, endpoint: LOCAL_ENGINE, cwd });
    this.created = true;
  }

  writeJournal(op, data = {}) {
    this.journal(op, { directory: this.directory, name: this.journalName,
      owner: this.owner, line: JSON.stringify(data) });
  }

  raw(args, { env = {}, input, timeout = 120_000, maxBuffer = 10 * 1024 * 1024 } = {}) {
    let result;
    try {
      result = this.invoke(this.binary, ["--host", LOCAL_ENGINE, ...args], {
        cwd: this.cwd, shell: false, windowsHide: true,
        env: safeEnvironment(env), input, timeout, maxBuffer, encoding: "utf8",
      });
    } catch { return { status: null, error: { code: "TRANSPORT" }, stdout: "", stderr: "" }; }
    return { ...result, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
  }

  checked(args) {
    const result = this.raw(args, { timeout: 20_000, maxBuffer: 2 * 1024 * 1024 });
    if (result.error || result.status !== 0) throw Error("Role fixture Docker ownership/endpoint observation unavailable.");
    return result.stdout.trim();
  }

  verifyEngine() {
    const result = this.raw(["info", "--format", "{{json .}}"], { timeout: 20_000 });
    let info;
    try { info = JSON.parse(result.stdout); } catch { /* fail closed */ }
    if (result.error || result.status !== 0 || info?.OSType !== "linux" ||
      !/^Docker Desktop(?:\b|$)/u.test(info?.OperatingSystem ?? "") ||
      typeof info?.ID !== "string" || info.ID.length < 8 ||
      (this.engineId !== null && info.ID !== this.engineId)) {
      throw Error("Role fixture refused unverified or changed local Docker Desktop engine.");
    }
    this.engineId = info.ID;
  }

  ensurePostgresImage() {
    this.verifyEngine();
    const inspect = () => this.raw(["image", "inspect", "--format", "{{json .}}", POSTGRES],
      { timeout: 20_000 });
    let result = inspect();
    if (result.error || result.status !== 0) {
      this.reserve("postgres_image_pull_intent", { image: POSTGRES, platform: "linux/amd64" });
      const pulled = this.raw(["pull", "--platform", "linux/amd64", POSTGRES],
        { timeout: 15 * 60_000, maxBuffer: 8 * 1024 * 1024 });
      if (pulled.error || pulled.status !== 0) {
        this.uncertain = true;
        throw Error(`Pinned PostgreSQL image pull failed; reconcile owner evidence: ${this.evidence}`);
      }
      result = inspect();
    }
    let image;
    try { image = JSON.parse(result.stdout); } catch { /* fail closed */ }
    if (result.error || result.status !== 0 || !ID.test((image?.Id ?? "").replace(/^sha256:/u, "")) ||
        image.Os !== "linux" || image.Architecture !== "amd64" ||
        !image.RepoDigests?.some((digest) => digest.endsWith(POSTGRES.slice(POSTGRES.indexOf("@"))))) {
      this.uncertain = true;
      throw Error(`Pinned PostgreSQL image manifest/platform identity unverified; reconcile: ${this.evidence}`);
    }
    this.reserve("verified_postgres_image", { id: image.Id, image: POSTGRES });
  }

  reserve(event, data) {
    this.writeJournal("append", { event, ...data });
  }

  observeContainer(name, fixture, kind, { expectNew = false } = {}) {
    const raw = this.checked(["inspect", "--type", "container", "--format", "{{json .}}", name]);
    let info;
    try { info = JSON.parse(raw); } catch { throw Error("Role fixture container ownership JSON unavailable."); }
    const existing = this.records.get(name);
    if (!ID.test(info?.Id ?? "") || info.Name !== `/${name}` ||
      info.Config?.Labels?.[RUN_LABEL] !== this.runId ||
      info.Config?.Labels?.[FIXTURE_LABEL] !== fixture ||
      info.Config?.Labels?.[KIND_LABEL] !== kind ||
      info.HostConfig?.Privileged !== false ||
      info.HostConfig?.NetworkMode !== `${fixture}-net` ||
      info.HostConfig?.Binds?.length ||
      info.Mounts?.some((mount) => mount.Type === "bind") ||
      Object.keys(info.HostConfig?.PortBindings ?? {}).length ||
      (kind === "postgres" && info.Config?.Image !== POSTGRES) ||
      (existing && existing.id !== info.Id) ||
      (expectNew && existing)) {
      throw Error("Role fixture container owner, ID or isolation proof rejected.");
    }
    if (this.image && kind === "migration-runner" && info.Image !== this.image.id) {
      throw Error("Role fixture migration runner immutable image digest mismatch.");
    }
    const record = { id: info.Id, name, fixture, kind };
    if (!existing) {
      this.reserve("observed_container", record);
      this.records.set(name, record);
    }
    return record;
  }

  getOwned(nameOrId) {
    const record = this.records.get(nameOrId) ??
      [...this.records.values()].find((record) => record.id === nameOrId);
    if (!record) throw Error("Role fixture refused an unrecorded or foreign container.");
    const observed = this.observeContainer(record.name, record.fixture, record.kind);
    if (observed.id !== record.id) throw Error("Role fixture container identity changed.");
    return record;
  }

  observeNetwork(name, fixture) {
    const raw = this.checked(["network", "inspect", "--format", "{{json .}}", name]);
    let info;
    try { info = JSON.parse(raw); } catch { throw Error("Role fixture network ownership JSON unavailable."); }
    if (!ID.test(info?.Id ?? "") || info.Name !== name || info.Driver !== "bridge" ||
      info.Internal !== true || info.Labels?.[RUN_LABEL] !== this.runId ||
      info.Labels?.[FIXTURE_LABEL] !== fixture ||
      (this.networks.has(name) && this.networks.get(name) !== info.Id)) {
      throw Error("Role fixture refused foreign or altered network.");
    }
    if (!this.networks.has(name)) {
      this.reserve("observed_network", { name, id: info.Id, fixture });
      this.networks.set(name, info.Id);
    }
    return info.Id;
  }

  observeVolume(name, fixture) {
    const raw = this.checked(["volume", "inspect", "--format", "{{json .}}", name]);
    let info;
    try { info = JSON.parse(raw); } catch { throw Error("Role fixture volume JSON unavailable."); }
    if (info?.Name !== name || info.Driver !== "local" ||
      info.Labels?.[RUN_LABEL] !== this.runId ||
      info.Labels?.[FIXTURE_LABEL] !== fixture ||
      (this.volumes.size && !this.volumes.has(name))) {
      throw Error("Role fixture refused foreign or altered named volume.");
    }
    if (!this.volumes.has(name)) {
      this.reserve("observed_volume", { name, fixture });
      this.volumes.add(name);
    }
  }

  call(args, options = {}) {
    this.verifyEngine();
    const [op, sub] = args;
    let transformed = args;
    let creation;
    if (op === "buildx" && sub === "build") {
      if (!args.includes("--load") || argument(args, "--platform") !== "linux/amd64" ||
        argument(args, "--progress") !== "plain" ||
        argument(args, "--file") !== "infra/Dockerfile.prod" ||
        argument(args, "--target") !== "migrator" ||
        args.length !== 18 || args.at(-1) !== "." ||
        !/^virki-role-test-migrator:[a-f0-9]{24}$/u.test(argument(args, "--tag") ?? "") ||
        !/^VIRKI_BUILD_REVISION=[a-f0-9]{40}$/u.test(argument(args, "--build-arg") ?? "") ||
        !args.includes("--label") || args[args.indexOf("--label") + 1] !== `${RUN_LABEL}=${this.runId}`) {
        throw Error("Role fixture rejected unexpected migration image build.");
      }
      this.imageTag = argument(args, "--tag");
      this.reserve("build_intent", { tag: this.imageTag });
    } else if (op === "network" && sub === "create") {
      const name = args.at(-1);
      const fixture = argument(args, "--label")?.split("=")[1];
      if (args.length !== 8 || !args.includes("--internal") ||
        !/^virki-role-(?:fresh|interrupted|populated)-[a-f0-9]{12}-net$/u.test(name ?? "") ||
        fixture !== this.runId || args[6] !== `${FIXTURE_LABEL}=${name.slice(0, -4)}`) {
        throw Error("Role fixture refused unapproved network creation.");
      }
      this.reserve("network_create_intent", { name });
      creation = { type: "network", name, fixture: name.slice(0, -4) };
    } else if (op === "volume" && sub === "create") {
      const name = args.at(-1);
      if (args.length !== 7 || !/^virki-role-interrupted-[a-f0-9]{12}-data$/u.test(name ?? "") ||
        argument(args, "--label") !== `${RUN_LABEL}=${this.runId}` ||
        args[5] !== `${FIXTURE_LABEL}=${name.slice(0, -5)}`) {
        throw Error("Role fixture refused unexpected volume creation.");
      }
      this.reserve("volume_create_intent", { name });
      creation = { type: "volume", name, fixture: name.slice(0, -5) };
    } else if (op === "create" || op === "run") {
      const name = argument(args, "--name");
      const fixture = args.find((entry) => entry.startsWith(`${FIXTURE_LABEL}=`))?.slice(FIXTURE_LABEL.length + 1);
      const kind = op === "create" ? "postgres" : "migration-runner";
      const own = args.filter((v) => v === `${RUN_LABEL}=${this.runId}`);
      const forbidden = args.some((part) => /^(?:--privileged(?:=|$)|--(?:pid|ipc|userns|uts|cgroupns|device|cap-add|security-opt|publish|publish-all|volumes-from|volume|add-host)(?:=|$)|--network=host$|-v$|-p$)/u.test(part));
      const allowedFixture = /^virki-role-(?:fresh|interrupted|populated)-[a-f0-9]{12}$/u.test(fixture ?? "");
      if (!allowedFixture || forbidden || !name?.startsWith(fixture) || own.length !== 1 ||
        !args.includes(`${KIND_LABEL}=${kind}`) ||
        argument(args, "--network") !== `${fixture}-net` ||
        (kind === "postgres" && (name !== fixture || argument(args, "--network-alias") !== "postgres")) ||
        (kind === "postgres" && args.at(-1) !== POSTGRES) ||
        (kind === "migration-runner" && (!/^virki-role-(?:fresh|interrupted|populated)-[a-f0-9]{12}-migrate-[a-f0-9]{12}$/u.test(name) ||
          !this.image || !args.includes(this.imageTag) || args.includes("--mount") || args.includes("--tmpfs")))) {
        throw Error("Role fixture refused unapproved container creation.");
      }
      if (kind === "postgres" && !identicalArgs(args, expectedPostgresCreate(fixture, this.runId))) {
        throw Error("Role fixture refused an unreviewed PostgreSQL creation profile.");
      }
      if (kind === "migration-runner" && !MIGRATOR_COMMANDS.some((command) =>
        ["DATABASE_URL", "MIGRATION_DATABASE_URL"].some((databaseKey) =>
          [false, true].some((retention) => identicalArgs(args,
            expectedMigrationRun(name, fixture, this.runId, this.imageTag, command, databaseKey, retention)))))) {
        throw Error("Role fixture refused an unreviewed migrator execution profile.");
      }
      if (kind === "migration-runner") {
        transformed = args.map((part) => part === this.imageTag ? this.image.id : part);
      }
      this.reserve("container_create_intent", { name, kind, fixture });
      creation = { type: "container", name, kind, fixture };
    } else if (["start", "stop", "rm", "exec", "cp", "logs", "inspect"].includes(op) &&
      !(op === "inspect" && args.includes("--type"))) {
      const index = op === "exec" ? (() => {
        let i = 1;
        while (args[i] === "--interactive" || args[i]?.startsWith("--env")) i += 1;
        return i;
      })() : op === "cp" || op === "logs" || op === "inspect" ? args.length - 1
        : args.length - 1;
      const mutable = args[index];
      let name = mutable;
      if (op === "cp") name = mutable.split(":/")[0];
      const owned = this.getOwned(name);
      transformed = [...args];
      transformed[index] = op === "cp" ? `${owned.id}:/${mutable.split(":/").slice(1).join(":/")}` : owned.id;
      if (["rm", "stop", "start", "exec", "cp"].includes(op)) this.reserve("container_mutation_intent", { id: owned.id, op });
    } else if (op === "network" && sub === "rm") {
      const name = [...this.networks.entries()].find(([n, id]) => n === args[2] || id === args[2])?.[0];
      if (!name) throw Error("Role fixture refused deleting an unowned network.");
      const fixture = name.slice(0, -4);
      transformed = ["network", "rm", this.observeNetwork(name, fixture)];
      this.reserve("network_remove_intent", { name, id: transformed[2] });
    } else if (op === "volume" && sub === "rm") {
      const name = args[2];
      if (!this.volumes.has(name)) throw Error("Role fixture refused deleting an unowned volume.");
      this.observeVolume(name, name.slice(0, -5));
      this.reserve("volume_remove_intent", { name });
    } else if (op === "image" && sub === "rm") {
      if (!this.image || (args[2] !== this.imageTag && args[2] !== this.image.id)) {
        throw Error("Role fixture refused deleting an unowned image.");
      }
      const metadata = this.checked(["image", "inspect", "--format", "{{json .}}", this.imageTag]);
      const info = JSON.parse(metadata);
      if (info.Id !== this.image.id || info.Config?.Labels?.[RUN_LABEL] !== this.runId ||
        !info.RepoTags?.includes(this.imageTag) || info.RepoTags.length !== 1) {
        throw Error("Role fixture refused image cleanup with altered tags/owner.");
      }
      // A tag may be retargeted between preflight and removal; remove only
      // the immutable digest already tied to our unique tag and owner label.
      transformed = ["image", "rm", this.image.id];
      this.reserve("image_remove_intent", { id: this.image.id, tag: this.imageTag });
    } else if (!(op === "ps" && ["--all", "--quiet"].every((flag) => args.includes(flag))) &&
      !(op === "network" && ["ls", "inspect"].includes(sub)) &&
      !(op === "volume" && ["ls", "inspect"].includes(sub)) &&
      !(op === "image" && sub === "inspect")) {
      throw Error("Role fixture denied an unreviewed Docker operation.");
    }

    // Docker timeouts are not proof of cancellation. Record the attempt before
    // invoking the daemon; never interpret a missing immediate CID as clean.
    const result = this.raw(transformed, options);
    if (creation) {
      try {
        if (creation.type === "container") {
          this.observeContainer(creation.name, creation.fixture, creation.kind);
        } else if (creation.type === "network") {
          this.observeNetwork(creation.name, creation.fixture);
        } else {
          this.observeVolume(creation.name, creation.fixture);
        }
      } catch {
        this.uncertain = true;
        throw Error(`Role fixture ${creation.type} start/identity uncertain. Reconcile owner evidence: ${this.evidence}`);
      }
    }
    if (result.error || result.status === null) this.uncertain = true;
    if (op === "image" && sub === "inspect" && result.status === 0 &&
      args.at(-1) === this.imageTag && !this.image) {
      const [id, run] = result.stdout.trim().split("|");
      if (ID.test(id.replace(/^sha256:/u, "")) && run === this.runId) {
        this.image = { id };
        this.reserve("observed_image", { id, tag: this.imageTag });
      }
    }
    if (result.status === 0 && ["start", "stop", "rm"].includes(op)) {
      const record = [...this.records.values()].find((r) => r.id === transformed.at(-1));
      if (op === "rm" && record) this.records.delete(record.name);
      if (record) return { ...result, stdout: record.name };
    }
    if (result.status === 0 && op === "network" && sub === "rm") this.networks.delete(args[2]);
    if (result.status === 0 && op === "volume" && sub === "rm") this.volumes.delete(args[2]);
    if (result.status === 0 && op === "image" && sub === "rm") this.image = null;
    return result;
  }

  ownedContainersForFixture(fixture) {
    return [...this.records.values()].filter((v) => v.fixture === fixture);
  }

  finish(success) {
    if (!this.created) return;
    if (!success || this.uncertain || this.records.size || this.networks.size ||
      this.volumes.size || this.image) {
      throw Error(`Role fixture owner evidence retained for operator reconciliation: ${this.evidence}`);
    }
    this.writeJournal("remove");
  }
}
