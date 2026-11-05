import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdtempSync, openSync, readdirSync, realpathSync, rmdirSync, rmSync, statSync, writeSync } from "node:fs";
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
export const LINUX_CI_DOCKER = "/usr/bin/docker";
export const LINUX_CI_ENGINE = "unix:///var/run/docker.sock";
const SECRET_ENV = /^(?:POSTGRES_(?:PASSWORD|DB|USER|HOST_AUTH_METHOD|INITDB_ARGS)|VIRKI_(?:RUNTIME_DB_PASSWORD|MIGRATOR_DB_PASSWORD|AUDIT_MAINTENANCE_DB_PASSWORD|E2E_DATABASE_PASSWORD|TEST_MIGRATOR_PASSWORD)|(?:MIGRATION_)?DATABASE_URL|PGPASSWORD|AUDIT_LOG_RETENTION_DAYS)$/u;

export function requireRoleFixtureLocalEnvironment(env = process.env, platform = process.platform) {
  const linuxCI = platform === "linux" && env.VIRKI_ROLE_FIXTURE_LINUX_CI === "1" &&
    env.GITHUB_ACTIONS === "true" && env.CI === "true" &&
    env.RUNNER_OS === "Linux" && env.RUNNER_ENVIRONMENT === "github-hosted" &&
    env.GITHUB_REPOSITORY === "bielxdh3/Virki" &&
    /^[1-9][0-9]{0,19}$/u.test(env.GITHUB_RUN_ID ?? "") &&
    /^[1-9][0-9]*$/u.test(env.GITHUB_RUN_ATTEMPT ?? "");
  const windows = platform === "win32" && !env.VIRKI_ROLE_FIXTURE_LINUX_CI;
  if ((!windows && !linuxCI) || Object.keys(env).some((key) =>
    /^(?:DOCKER_|COMPOSE_|NODE_OPTIONS$|NODE_EXTRA_CA_CERTS$|DATABASE_URL$|MIGRATION_DATABASE_URL$|PG(?:PASSWORD|HOST|PORT|SERVICE|PASSFILE|OPTIONS)$)/iu.test(key))) {
    throw new Error("Role fixture requires local Windows Docker Desktop or explicitly opted-in hosted Linux CI, with no Docker/Node/database overrides.");
  }
  return linuxCI ? "linux-ci" : "windows-local";
}

function safeEnvironment(extra, mode = "windows-local") {
  if (Object.keys(extra).some((key) => !SECRET_ENV.test(key))) throw Error("Role fixture rejected an unexpected subprocess variable.");
  if (mode === "linux-ci") return { PATH: "/usr/bin:/bin", HOME: "/nonexistent", LANG: "C", ...extra };
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

// A hosted runner and root-owned local socket are CI trust assumptions: neither
// environment hints nor daemon responses attest an independent host identity.
export function inspectRoleLinuxSocket({
  stat = statSync, canonicalize = realpathSync, hostname = os.hostname,
} = {}) {
  let socket, binary;
  try {
    socket = stat("/var/run/docker.sock");
    binary = stat(LINUX_CI_DOCKER);
    if (canonicalize("/var/run/docker.sock") !== "/run/docker.sock" ||
      canonicalize(LINUX_CI_DOCKER) !== LINUX_CI_DOCKER) throw Error("redirected");
  } catch { throw Error("Role fixture Linux CI Docker socket or executable untrusted."); }
  if (!socket.isSocket() || socket.uid !== 0 || (socket.mode & 0o002) ||
    !binary.isFile() || binary.uid !== 0 || (binary.mode & 0o002) ||
    !Number.isSafeInteger(socket.dev) || !Number.isSafeInteger(socket.ino) ||
    !/^[A-Za-z0-9][A-Za-z0-9.-]{0,253}$/u.test(hostname())) {
    throw Error("Role fixture Linux CI Docker socket or executable untrusted.");
  }
  return { dev: socket.dev, ino: socket.ino, hostname: hostname() };
}

// Dedicated, exclusive 0700 directory. Every line is flushed before daemon
// contact; keep evidence on any uncertain result for manual reconciliation.
export function runProtectedLinuxRoleJournal(operation, request) {
  const { directory, name, owner, line } = request;
  if (!/^virki-offline-fixture-[a-f0-9]{32}$/u.test(name) ||
    !/^[a-f0-9]{32}$/u.test(owner) || name !== `virki-offline-fixture-${owner}` ||
    !directory.startsWith(path.join(os.tmpdir(), "virki-role-owner-"))) {
    throw Error("Invalid private Linux role fixture journal identity.");
  }
  const entry = lstatSync(directory);
  if (!entry.isDirectory() || entry.isSymbolicLink() || entry.uid !== process.getuid() ||
    (entry.mode & 0o077) !== 0 || realpathSync(directory) !== directory) {
    throw Error("Linux role fixture journal directory is not private.");
  }
  const filename = path.join(directory, `${name}.jsonl`);
  if (operation === "remove") {
    // Only a finished, already reconciled owner may request deletion.
    const file = lstatSync(filename);
    if (!file.isFile() || file.isSymbolicLink() || file.uid !== process.getuid() ||
      (file.mode & 0o077) !== 0 || file.nlink !== 1) throw Error("Unsafe Linux role fixture journal removal.");
    // A foreign sibling is evidence of an uncertain owner directory. Never
    // erase the only journal and then discover that the directory is nonempty.
    if (!identicalArgs(readdirSync(directory), [`${name}.jsonl`])) {
      throw Error("Linux role fixture journal directory contains unexpected entries.");
    }
    rmSync(filename);
    fsyncDirectory(directory);
    // Only the now-empty, private directory may be removed; recursive removal
    // would permit accidental deletion of independently created evidence.
    rmdirSync(directory);
    fsyncDirectory(path.dirname(directory));
    return;
  }
  if (!["create", "append"].includes(operation) || typeof line !== "string" ||
    !line || line.length > 16_384 || /[\r\n]/u.test(line)) throw Error("Invalid role fixture journal entry.");
  const flags = (operation === "create" ? constants.O_CREAT | constants.O_EXCL : constants.O_APPEND) |
    constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC;
  let fd;
  try {
    fd = openSync(filename, flags, 0o600);
    const file = lstatSync(filename);
    if (!file.isFile() || file.isSymbolicLink() || file.uid !== process.getuid() ||
      (file.mode & 0o077) !== 0 || file.nlink !== 1) throw Error("Unsafe role fixture journal inode.");
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.ino !== file.ino || opened.dev !== file.dev) {
      throw Error("Role fixture journal pathname changed.");
    }
    writeSync(fd, `${line}\n`);
    fsyncSync(fd);
    const after = fstatSync(fd);
    const pathAfter = lstatSync(filename);
    if (opened.ino !== after.ino || opened.dev !== after.dev ||
      after.ino !== pathAfter.ino || after.dev !== pathAfter.dev) {
      throw Error("Role fixture journal inode changed during append.");
    }
  } finally { if (fd !== undefined) closeSync(fd); }
  fsyncDirectory(directory);
}

function fsyncDirectory(directory) {
  const fd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function createDurableLinuxOwnerDirectory() {
  const directory = mkdtempSync(path.join(os.tmpdir(), "virki-role-owner-"));
  try {
    // fsync the parent too: a flushed journal inode is insufficient if the
    // newly created 0700 directory entry disappears after a host crash.
    fsyncDirectory(path.dirname(directory));
    return directory;
  } catch {
    rmdirSync(directory);
    throw Error("Linux role fixture could not durably reserve its private journal directory.");
  }
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

const CONTAINER_FORMATS = new Set([
  `--format={{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}starting{{end}}`,
  `--format={{range $port, $bindings := .HostConfig.PortBindings}}{{range $bindings}}published{{end}}{{end}}|{{range $port, $bindings := .NetworkSettings.Ports}}{{range $bindings}}published{{end}}{{end}}|{{.HostConfig.NetworkMode}}|{{index .Config.Labels "virki.role-test.run"}}|{{index .Config.Labels "virki.role-test.fixture"}}|{{index .Config.Labels "virki.role-test.kind"}}`,
  `--format={{index .HostConfig.Tmpfs "/var/lib/postgresql/data"}}`,
  `--format={{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}|{{.Name}}|{{.Destination}}{{end}}{{end}}`,
  `--format={{range .Mounts}}{{if eq .Destination "/var/lib/postgresql/data"}}{{.Type}}{{end}}{{end}}`,
  "--format={{len .HostConfig.Binds}}",
  `--format={{.Name}}|{{index .Config.Labels "virki.role-test.run"}}|{{index .Config.Labels "virki.role-test.fixture"}}|{{index .Config.Labels "virki.role-test.kind"}}`,
]);
const NETWORK_FORMATS = new Set([
  `--format={{.Name}}|{{.Driver}}|{{.Internal}}|{{index .Labels "virki.role-test.run"}}|{{index .Labels "virki.role-test.fixture"}}`,
  `--format={{.Name}}|{{.Internal}}|{{index .Labels "virki.role-test.run"}}|{{index .Labels "virki.role-test.fixture"}}|{{len .Containers}}`,
]);
const VOLUME_FORMAT = `--format={{.Name}}|{{.Driver}}|{{index .Labels "virki.role-test.run"}}|{{index .Labels "virki.role-test.fixture"}}`;
const IMAGE_FORMATS = new Set([
  `--format={{.Id}}|{{index .Config.Labels "virki.role-test.run"}}|{{index .Config.Labels "org.opencontainers.image.revision"}}`,
  `--format={{.Id}}|{{index .Config.Labels "virki.role-test.run"}}`,
  "--format={{.Id}}",
]);
const FIXTURE_NAME = /^virki-role-(?:fresh|interrupted|populated)-[a-f0-9]{12}$/u;
const MIGRATOR_NAME = /^virki-role-(?:fresh|interrupted|populated)-[a-f0-9]{12}-migrate-[a-f0-9]{12}$/u;
const ROLE_PATHS = new Set([
  "/docker-entrypoint-initdb.d/10-virki-database-roles.sh",
  "/docker-entrypoint-initdb.d/20-virki-e2e-runtime-test-role.sh",
  "/test/10-virki-database-roles.sh",
  "/test/20-virki-e2e-runtime-test-role.sh",
]);
const PSQL_PREFIX = ["psql", "--no-psqlrc", "--host", "127.0.0.1", "--username"];
const DB_SUFFIX = ["--dbname", "virki_roles_test", "--set", "ON_ERROR_STOP=1"];

// Validate the COMPLETE argv before even observing the engine. Docker accepts
// multiple targets and mixed positional/options after flags: checking only an
// owned last operand lets a foreign first operand be modified or removed.
function requireReviewedRoleArguments(args, state) {
  if (!Array.isArray(args) || args.some((v) => typeof v !== "string")) throw Error("Unreviewed role fixture Docker arguments.");
  const [op, sub] = args;
  const fixture = (v) => FIXTURE_NAME.test(v ?? "");
  const network = (v) => fixture(v?.slice(0, -4)) && v.endsWith("-net");
  const volume = (v) => /^virki-role-interrupted-[a-f0-9]{12}-data$/u.test(v ?? "");
  const container = (v) => fixture(v) || MIGRATOR_NAME.test(v ?? "") || ID.test(v ?? "");
  const image = (v) => v === state.imageTag || v === state.image?.id;
  let allowed = false;
  if (op === "network") {
    if (sub === "create") {
      const n = args.at(-1);
      allowed = network(n) && identicalArgs(args, ["network", "create", "--internal",
        "--label", `${RUN_LABEL}=${state.runId}`, "--label", `${FIXTURE_LABEL}=${n.slice(0, -4)}`, n]);
    } else if (sub === "rm") allowed = args.length === 3 && (network(args[2]) || ID.test(args[2]));
    else if (sub === "ls") allowed = args.length === 5 && identicalArgs(args, ["network", "ls", "--quiet", "--filter", `name=^${args[4]?.slice(6, -1)}$`]) && network(args[4]?.slice(6, -1));
    else if (sub === "inspect") allowed = args.length === 4 && NETWORK_FORMATS.has(args[2]) &&
      [...state.networks].some(([name, id]) => name === args[3] || id === args[3] ||
        (/^[a-f0-9]{12,64}$/u.test(args[3] ?? "") && id.startsWith(args[3])));
  } else if (op === "volume") {
    if (sub === "create") {
      const v = args.at(-1);
      allowed = volume(v) && identicalArgs(args, ["volume", "create",
        "--label", `${RUN_LABEL}=${state.runId}`, "--label", `${FIXTURE_LABEL}=${v.slice(0, -5)}`, v]);
    } else if (sub === "rm") allowed = args.length === 3 && volume(args[2]);
    else if (sub === "ls") allowed = args.length === 5 && volume(args[4]?.slice(6, -1)) &&
      identicalArgs(args, ["volume", "ls", "--quiet", "--filter", `name=^${args[4].slice(6, -1)}$`]);
    else if (sub === "inspect") allowed = args.length === 4 && args[2] === VOLUME_FORMAT && state.volumes.has(args[3]);
  } else if (op === "buildx" && sub === "build") {
    const tag = args[16];
    allowed = /^virki-role-test-migrator:[a-f0-9]{24}$/u.test(tag ?? "") &&
      identicalArgs(args, ["buildx", "build", "--load", "--platform", "linux/amd64",
        "--progress", "plain", "--file", "infra/Dockerfile.prod", "--target", "migrator",
        "--build-arg", args[12], "--label", `${RUN_LABEL}=${state.runId}`,
        "--tag", tag, "."]) &&
      /^VIRKI_BUILD_REVISION=[a-f0-9]{40}$/u.test(args[12]);
  } else if (op === "create") {
    allowed = fixture(args[2]) && identicalArgs(args, expectedPostgresCreate(args[2], state.runId));
  } else if (op === "run") {
    const n = args[2];
    // The fixture ID is the fixed prefix before the trailing migration suffix.
    const parent = n?.replace(/-migrate-[a-f0-9]{12}$/u, "");
    allowed = MIGRATOR_NAME.test(n ?? "") && !!state.image && !!state.imageTag &&
      MIGRATOR_COMMANDS.some((cmd) => ["DATABASE_URL", "MIGRATION_DATABASE_URL"].some((key) =>
        [false, true].some((retention) =>
          identicalArgs(args, expectedMigrationRun(n, parent, state.runId, state.imageTag, cmd, key, retention)))));
  } else if (["start", "stop", "rm"].includes(op)) {
    allowed = container(args.at(-1)) &&
      (op === "rm" ? (args.length === 2 || identicalArgs(args, ["rm", "--force", args[2]])) : args.length === 2);
  } else if (op === "cp") {
    const dest = args[2]?.split(":/");
    const basename = dest?.[1]?.split("/").at(-1);
    const expectedSource = basename === "10-virki-database-roles.sh"
      ? path.join(state.cwd, "infra", "postgres-init", basename)
      : basename === "20-virki-e2e-runtime-test-role.sh"
        ? path.join(state.cwd, "scripts", "e2e", basename) : null;
    allowed = args.length === 3 && container(dest?.[0]) && dest?.length === 2 &&
      ROLE_PATHS.has(`/${dest[1]}`) && args[1] === expectedSource;
  } else if (op === "logs") {
    allowed = args.length === 4 && identicalArgs(args, ["logs", "--tail", "40", args[3]]) && container(args[3]);
  } else if (op === "inspect") {
    allowed = args.length === 3 && CONTAINER_FORMATS.has(args[1]) && container(args[2]);
  } else if (op === "image") {
    if (sub === "rm") allowed = args.length === 3 && image(args[2]);
    else if (sub === "inspect") allowed = args.length === 4 && IMAGE_FORMATS.has(args[2]) && image(args[3]);
  } else if (op === "ps") {
    const filters = args.slice(4);
    allowed = args.length >= 5 && args.length <= 8 &&
      identicalArgs(args.slice(0, 4), ["ps", "--all", "--quiet", "--filter"]) &&
      (args.length === 5 && (
        /^name=\^\/virki-role-(?:fresh|interrupted|populated)-[a-f0-9]{12}\$$/u.test(filters[0]) ||
        /^volume=virki-role-interrupted-[a-f0-9]{12}-data$/u.test(filters[0]) ||
        /^ancestor=sha256:[a-f0-9]{64}$/u.test(filters[0])) ||
        args.length === 7 && filters[0] === `label=${RUN_LABEL}=${state.runId}` &&
        filters[1] === "--filter" && /^label=virki\.role-test\.fixture=virki-role-(?:fresh|interrupted|populated)-[a-f0-9]{12}$/u.test(filters[2]));
  } else if (op === "exec") {
    let index = 1;
    const interactive = args[index] === "--interactive";
    if (interactive) index += 1;
    const vars = [];
    while (args[index]?.startsWith("--env=")) vars.push(args[index++]);
    const target = args[index++];
    const command = args.slice(index);
    const scripts = ["--env=VIRKI_RUNTIME_DB_PASSWORD", "--env=VIRKI_MIGRATOR_DB_PASSWORD", "--env=VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD"];
    allowed = container(target) && (
      (!interactive && vars.length === 0 && identicalArgs(command, ["mkdir", "-m", "0700", "/test"]) && index === 2) ||
      (!interactive && vars.length === 0 && command.length === 2 && command[0] === "sha256sum" && ROLE_PATHS.has(command[1])) ||
      (!interactive && vars.length === 0 && command.length === 3 && identicalArgs(command.slice(0, 2), ["test", "-e"]) && ROLE_PATHS.has(command[2])) ||
      (!interactive && identicalArgs(vars, scripts) && command.length === 2 && command[0] === "sh" && ROLE_PATHS.has(command[1]) && command[1].endsWith("/10-virki-database-roles.sh")) ||
      (!interactive && identicalArgs(vars, ["--env=VIRKI_E2E_DATABASE_PASSWORD"]) && command.length === 2 && command[0] === "sh" && command[1].endsWith("/20-virki-e2e-runtime-test-role.sh") && ROLE_PATHS.has(command[1])) ||
      (!interactive && identicalArgs(vars, ["--env=PGPASSWORD"]) && command.length === 14 &&
        identicalArgs(command.slice(0, 5), PSQL_PREFIX) &&
        ["virki_bootstrap", "virki_runtime", "virki_runtime_test", "virki_migrator", "virki_audit_maintenance", "virki_connect_probe"].includes(command[5]) &&
        identicalArgs(command.slice(6, 10), DB_SUFFIX) &&
        identicalArgs(command.slice(10, 14), ["--tuples-only", "--no-align", "--command", command[13]]) &&
        typeof command[13] === "string" && command[13].length > 0 && command[13].length < 32_768) ||
      (!interactive && identicalArgs(vars, ["--env=PGPASSWORD"]) &&
        identicalArgs(command, [...PSQL_PREFIX, "virki_runtime", ...DB_SUFFIX, "--command",
          "CREATE TABLE public.__virki_forbidden_probe (id integer);"])) ||
      (interactive && identicalArgs(vars, ["--env=VIRKI_TEST_MIGRATOR_PASSWORD"]) &&
        identicalArgs(command, ["psql", "--no-psqlrc", "--username", "virki_bootstrap",
          "--dbname", "virki_roles_test", "--set", "ON_ERROR_STOP=1"]))
    );
  }
  if (!allowed) throw Error("Role fixture denied unreviewed Docker arguments before daemon contact.");
}

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

function requireLocalDefaultBuildxBuilder(stdout) {
  // The signed plugin must resolve its own default builder through the fresh
  // Docker configuration, rather than a remembered remote/container builder.
  // Recent Docker Desktop adds a "Devices" section containing more "Name:"
  // fields; these describe BuildKit devices, not additional builder nodes.
  const lines = typeof stdout === "string" ? stdout.split(/\r?\n/u).map((line) => line.trim()) : [];
  const nodesAt = lines.indexOf("Nodes:");
  const tailAt = lines.findIndex((line, at) => at > nodesAt &&
    /^(?:Labels:|Devices:|GC Policy rule#[0-9]+:)$/u.test(line));
  const builder = nodesAt > 0 ? lines.slice(0, nodesAt) : [];
  const node = nodesAt > 0 ? lines.slice(nodesAt + 1, tailAt < 0 ? undefined : tailAt) : [];
  const values = (section, key) => section.filter((line) => line.startsWith(`${key}:`))
    .map((line) => line.slice(key.length + 1).trim());
  if (!identicalArgs(values(builder, "Name"), ["default"]) ||
      !identicalArgs(values(builder, "Driver"), ["docker"]) ||
      !identicalArgs(values(node, "Name"), ["default"]) ||
      !identicalArgs(values(node, "Endpoint"), ["default"]) ||
      !identicalArgs(values(node, "Status"), ["running"])) {
    throw Error("Role fixture Buildx default builder identity/driver/endpoint untrusted.");
  }
}

function assertUntouchedBuildxConfig(directory, original) {
  const current = lstatSync(directory);
  if (!current.isDirectory() || current.isSymbolicLink() ||
    current.dev !== original.dev || current.ino !== original.ino ||
    realpathSync.native(directory).toLowerCase() !== directory.toLowerCase()) {
    throw Error("Role fixture Buildx private configuration identity/contents changed.");
  }
  const rootNames = readdirSync(directory);
  // The signed Docker Desktop Buildx inspect creates precisely its private
  // empty bookkeeping folders and zero-byte lock. A remote instance, saved
  // default, config.json, extra plugin path, or unfamiliar file is rejected.
  if (rootNames.length === 0) return;
  if (!identicalArgs(rootNames, ["buildx"])) {
    throw Error("Role fixture Buildx private configuration identity/contents changed.");
  }
  const statePath = path.join(directory, "buildx");
  const state = lstatSync(statePath);
  if (!state.isDirectory() || state.isSymbolicLink() ||
      !identicalArgs(readdirSync(statePath).sort(), [".lock", "activity", "defaults", "instances"])) {
    throw Error("Role fixture Buildx private configuration identity/contents changed.");
  }
  for (const name of ["activity", "defaults", "instances"]) {
    const entryPath = path.join(statePath, name);
    const entry = lstatSync(entryPath);
    if (!entry.isDirectory() || entry.isSymbolicLink() || readdirSync(entryPath).length !== 0) {
      throw Error("Role fixture Buildx private configuration identity/contents changed.");
    }
  }
  const lock = lstatSync(path.join(statePath, ".lock"));
  if (!lock.isFile() || lock.isSymbolicLink() || lock.size !== 0 || lock.nlink !== 1) {
    throw Error("Role fixture Buildx private configuration identity/contents changed.");
  }
}

function removeVerifiedBuildxConfig(directory, original) {
  if (!original) throw Error("Missing Buildx configuration inode.");
  const after = lstatSync(directory);
  if (!after.isDirectory() || after.isSymbolicLink() ||
    after.dev !== original.dev || after.ino !== original.ino ||
    realpathSync.native(directory).toLowerCase() !== directory.toLowerCase()) {
    throw Error("Buildx configuration directory replaced.");
  }
  rmSync(directory, { recursive: true });
}

// No caller may use a mutable name as authority: each mutation and every
// container read operation is rebound to a previously observed immutable ID.
export class OwnedRoleDocker {
  constructor({ runId, cwd, invoke = spawnSync, journal = runProtectedWindowsJournalOperation,
    verify = verifyTrustedWindowsDockerCli, verifyBuildx = verifyOfficialBuildx,
    linuxProbe = inspectRoleLinuxSocket, env = process.env, platform = process.platform }) {
    this.mode = requireRoleFixtureLocalEnvironment(env, platform);
    if (!/^[a-f0-9]{24}$/u.test(runId)) throw Error("Invalid role fixture run ID.");
    this.invoke = invoke;
    this.linuxProbe = linuxProbe;
    this.linuxIdentity = this.mode === "linux-ci" ? linuxProbe() : null;
    this.binary = this.mode === "linux-ci" ? LINUX_CI_DOCKER : invoke === spawnSync ? verify() : DOCKER_EXE;
    if (invoke === spawnSync && this.mode === "windows-local") verifyBuildx();
    this.verifyBuildx = invoke === spawnSync && this.mode === "windows-local" ? verifyBuildx : null;
    this.engine = this.mode === "linux-ci" ? LINUX_CI_ENGINE : LOCAL_ENGINE;
    this.cwd = cwd;
    this.runId = runId;
    this.journal = this.mode === "linux-ci" && journal === runProtectedWindowsJournalOperation
      ? runProtectedLinuxRoleJournal : journal;
    this.owner = randomBytes(16).toString("hex");
    this.journalName = `virki-offline-fixture-${this.owner}`;
    this.directory = this.mode === "linux-ci"
      ? platform === process.platform && journal === runProtectedWindowsJournalOperation
        ? createDurableLinuxOwnerDirectory()
        : path.join(os.tmpdir(), `virki-role-owner-${this.owner}`)
      : path.join(os.homedir(), ".virki", "offline-docker-reconciliation");
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
    this.writeJournal("create", { event: "run_reservation", runId, owner: this.owner, endpoint: this.engine, cwd });
    this.created = true;
  }

  writeJournal(op, data = {}) {
    this.journal(op, { directory: this.directory, name: this.journalName,
      owner: this.owner, line: JSON.stringify(data) });
  }

  #raw(args, { env = {}, input, timeout = 120_000, maxBuffer = 10 * 1024 * 1024 } = {}) {
    this.assertEndpoint();
    if (this.mode === "windows-local" && args[0] === "buildx" && args[1] === "build") {
      // docker.exe resolves cli-plugins under the mutable user profile before
      // its system plugin. Launch the checked ProgramFiles Buildx executable
      // itself; never ask docker.exe to search for a buildx plugin.
      return this.#signedBuildx(args, { env, input, timeout, maxBuffer });
    }
    if (this.mode === "linux-ci" && args[0] === "buildx" && args[1] === "build") {
      return this.#isolatedLinuxBuildx(args, { env, input, timeout, maxBuffer });
    }
    let result;
    try {
      result = this.invoke(this.binary, ["--host", this.engine, ...args], {
        cwd: this.cwd, shell: false, windowsHide: true,
        env: safeEnvironment(env, this.mode), input, timeout, maxBuffer, encoding: "utf8",
      });
    } catch { return { status: null, error: { code: "TRANSPORT" }, stdout: "", stderr: "" }; }
    return { ...result, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
  }

  #signedBuildx(args, { env, input, timeout, maxBuffer }) {
    this.verifyBuildx?.();
    // A new configuration blocks HOME/.docker/config.json cliPluginsExtraDirs,
    // persisted contexts and user-selected Buildx builders for this process.
    // Keep HOME/APPDATA for Windows runtime compatibility; they are not used
    // to select a CLI plugin since the signed plugin runs by absolute path.
    const configDir = mkdtempSync(path.join(os.tmpdir(), "virki-role-buildx-"));
    let configInfo, response, failure;
    try {
      configInfo = lstatSync(configDir);
      if (!configInfo.isDirectory() || configInfo.isSymbolicLink() ||
        realpathSync.native(configDir).toLowerCase() !== configDir.toLowerCase()) {
        throw Error("Role fixture Buildx private configuration directory untrusted.");
      }
      const environment = {
        ...safeEnvironment(env, this.mode),
        DOCKER_HOST: this.engine,
        DOCKER_CONFIG: configDir,
        BUILDX_CONFIG: path.join(configDir, "buildx"),
      };
      const run = (argv, options) => this.invoke(BUILDX, argv, {
        cwd: this.cwd, shell: false, windowsHide: true, encoding: "utf8",
        env: environment, ...options,
      });
      // The probe is read-only. The explicit default builder uses the pinned
      // local Docker Desktop pipe, with the in-engine 'docker' Buildx driver.
      const inspect = run(["--builder", "default", "inspect", "default"],
        { timeout: 20_000, maxBuffer: 64 * 1024 });
      if (inspect.error || inspect.status !== 0) {
        throw Error("Role fixture Buildx default builder preflight unavailable.");
      }
      requireLocalDefaultBuildxBuilder(inspect.stdout);
      assertUntouchedBuildxConfig(configDir, configInfo);
      let result;
      try {
        result = run(["--builder", "default", ...args.slice(1)], { input, timeout, maxBuffer });
      } catch {
        result = { status: null, error: { code: "TRANSPORT" }, stdout: "", stderr: "" };
      }
      response = { ...result, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
    } catch (cause) {
      this.uncertain = true;
      failure = cause;
    } finally {
      // The directory was created exclusively for this invocation. Keep it
      // only if cleanup itself is uncertain; preserve the run journal in that
      // case instead of silently treating the operation as complete.
      try { removeVerifiedBuildxConfig(configDir, configInfo); }
      catch {
        this.uncertain = true;
        failure = Error("Role fixture Buildx temporary configuration cleanup uncertain.");
      }
    }
    if (failure) throw failure;
    return response;
  }

  #isolatedLinuxBuildx(args, { env, input, timeout, maxBuffer }) {
    // A hosted runner must not resolve Buildx state against HOME=/nonexistent,
    // and must never inherit a user-selected remote builder or Docker config.
    // Docker's own system plugin is selected by the verified /usr/bin/docker
    // executable with a fresh explicit config and pinned local Unix socket.
    const configDir = mkdtempSync(path.join(os.tmpdir(), "virki-role-ci-buildx-"), { mode: 0o700 });
    let configInfo, response, failure;
    try {
      configInfo = lstatSync(configDir);
      if (!configInfo.isDirectory() || configInfo.isSymbolicLink() ||
          realpathSync.native(configDir) !== configDir ||
          (process.platform === "linux" &&
            (configInfo.uid !== process.getuid() || (configInfo.mode & 0o077) !== 0))) {
        throw Error("Role fixture Linux Buildx private configuration directory untrusted.");
      }
      const environment = {
        ...safeEnvironment(env, this.mode),
        DOCKER_HOST: this.engine,
        DOCKER_CONFIG: configDir,
        BUILDX_CONFIG: path.join(configDir, "buildx"),
      };
      const run = (argv, options) => this.invoke(this.binary,
        ["--host", this.engine, "buildx", "--builder", "default", ...argv], {
          cwd: this.cwd, shell: false, windowsHide: true, encoding: "utf8",
          env: environment, ...options,
        });
      const inspect = run(["inspect", "default"], { timeout: 20_000, maxBuffer: 64 * 1024 });
      if (inspect.error || inspect.status !== 0) {
        throw Error("Role fixture Linux Buildx default builder preflight unavailable.");
      }
      requireLocalDefaultBuildxBuilder(inspect.stdout);
      assertUntouchedBuildxConfig(configDir, configInfo);
      let result;
      try {
        result = run(args.slice(1), { input, timeout, maxBuffer });
      } catch {
        result = { status: null, error: { code: "TRANSPORT" }, stdout: "", stderr: "" };
      }
      response = { ...result, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
    } catch (cause) {
      this.uncertain = true;
      failure = cause;
    } finally {
      try { removeVerifiedBuildxConfig(configDir, configInfo); }
      catch {
        this.uncertain = true;
        failure = Error("Role fixture Linux Buildx temporary configuration cleanup uncertain.");
      }
    }
    if (failure) throw failure;
    return response;
  }

  assertEndpoint() {
    if (this.linuxIdentity) {
      const current = this.linuxProbe();
      if (current.dev !== this.linuxIdentity.dev || current.ino !== this.linuxIdentity.ino ||
        current.hostname !== this.linuxIdentity.hostname) {
        throw Error("Role fixture Linux CI Docker socket identity changed.");
      }
    }
  }

  #checked(args) {
    const result = this.#raw(args, { timeout: 20_000, maxBuffer: 2 * 1024 * 1024 });
    if (result.error || result.status !== 0) throw Error("Role fixture Docker ownership/endpoint observation unavailable.");
    return result.stdout.trim();
  }

  verifyEngine() {
    const result = this.#raw(["info", "--format", "{{json .}}"], { timeout: 20_000 });
    let info;
    try { info = JSON.parse(result.stdout); } catch { /* fail closed */ }
    if (result.error || result.status !== 0 || info?.OSType !== "linux" ||
      (this.mode === "linux-ci"
        ? info?.Name !== this.linuxIdentity.hostname || /Docker Desktop/u.test(info?.OperatingSystem ?? "")
        : !/^Docker Desktop(?:\b|$)/u.test(info?.OperatingSystem ?? "")) ||
      typeof info?.ID !== "string" || info.ID.length < 8 ||
      (this.engineId !== null && info.ID !== this.engineId)) {
      throw Error("Role fixture refused unverified or changed local Docker Desktop engine.");
    }
    this.engineId = info.ID;
  }

  ensurePostgresImage() {
    this.verifyEngine();
    const inspect = () => this.#raw(["image", "inspect", "--format", "{{json .}}", POSTGRES],
      { timeout: 20_000 });
    let result = inspect();
    if (result.error || result.status !== 0) {
      this.reserve("postgres_image_pull_intent", { image: POSTGRES, platform: "linux/amd64" });
      const pulled = this.#raw(["pull", "--platform", "linux/amd64", POSTGRES],
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
    if (!(FIXTURE_NAME.test(name) || MIGRATOR_NAME.test(name)) ||
      !FIXTURE_NAME.test(fixture) || !["postgres", "migration-runner"].includes(kind)) {
      throw Error("Role fixture refused an unreviewed container observation.");
    }
    const raw = this.#checked(["inspect", "--type", "container", "--format", "{{json .}}", name]);
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
    if (name !== `${fixture}-net` || !FIXTURE_NAME.test(fixture)) {
      throw Error("Role fixture refused an unreviewed network observation.");
    }
    const raw = this.#checked(["network", "inspect", "--format", "{{json .}}", name]);
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
    if (name !== `${fixture}-data` || !/^virki-role-interrupted-[a-f0-9]{12}$/u.test(fixture)) {
      throw Error("Role fixture refused an unreviewed volume observation.");
    }
    const raw = this.#checked(["volume", "inspect", "--format", "{{json .}}", name]);
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
    requireReviewedRoleArguments(args, this);
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
      const metadata = this.#checked(["image", "inspect", "--format", "{{json .}}", this.imageTag]);
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
    const result = this.#raw(transformed, options);
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
