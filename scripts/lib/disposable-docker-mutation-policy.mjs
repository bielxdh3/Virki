// A deliberately narrow, test-only Docker command policy. The caller can
// describe only its own smoke fixtures, never forward arbitrary daemon verbs.
import path from "node:path";
import { fileURLToPath } from "node:url";

const POSTGRES = "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24";
const ROLE_SETUP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "infra",
  "postgres-init", "10-virki-database-roles.sh") + ":/docker-entrypoint-initdb.d/10-virki-database-roles.sh:ro";
const ENV_NAMES = {
  "create-public": new Set(["NODE_ENV", "VIRKI_PORTAL_URL"]),
  "create-issuer": new Set(["NODE_ENV", "OIDC_ISSUER_PORT", "VIRKI_OIDC_ISSUER",
    "VIRKI_OIDC_SIGNING_JWKS", "VIRKI_OIDC_COOKIE_KEY", "VIRKI_OIDC_ADAPTER_KEY",
    "VIRKI_TOTP_ENCRYPTION_KEY", "DATABASE_URL"]),
  "create-hub": new Set(["NODE_ENV", "VIRKI_HUB_URL", "VIRKI_PORTAL_URL", "VIRKI_HUB_HOSTNAME",
    "VIRKI_PORTAL_HOSTNAME", "VIRKI_OIDC_PROXY_URL", "DATABASE_URL", "VIRKI_RATE_LIMIT_HASH_SECRET",
    "VIRKI_AUDIT_HASH_SECRET", "VIRKI_CSRF_SIGNING_KEY", "VIRKI_TOTP_ENCRYPTION_KEY",
    "VIRKI_EMAIL_OUTBOX_KEY", "VIRKI_OIDC_ADAPTER_KEY", "CLOUDFLARE_ACCESS_JWT_REQUIRED",
    "CLOUDFLARE_ACCESS_AUDIENCE", "CLOUDFLARE_TEAM_DOMAIN"]),
  "create-database": new Set(["POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB",
    "VIRKI_RUNTIME_DB_PASSWORD", "VIRKI_MIGRATOR_DB_PASSWORD",
    "VIRKI_AUDIT_MAINTENANCE_DB_PASSWORD"]),
  "run-deploy": new Set(["MIGRATION_DATABASE_URL"]),
  "run-status": new Set(["MIGRATION_DATABASE_URL"]),
  "run-assertion": new Set(),
};
const WITH_VALUE = new Set(["--name", "--network", "--label", "--cap-drop", "--security-opt",
  "--tmpfs", "--publish", "--env", "--network-alias", "--volume", "--entrypoint"]);
const BOOLEAN = new Set(["--rm", "--detach", "--read-only"]);
const TMPFS = new Set([
  "/tmp:rw,noexec,nosuid,nodev,size=64m",
  "/app/apps/public-site/.next/cache:rw,noexec,nosuid,nodev,size=128m",
  "/app/apps/hub/.next/cache:rw,noexec,nosuid,nodev,size=128m",
]);
const same = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);

export function requireOwnedDisposableDockerMutation({ kind, owner, containers, network, stage, args }) {
  const refuse = () => { throw Error("Disposable Docker mutation refused: unreviewed stage, flags, resource or image."); };
  if (!Array.isArray(args) || args.some((value) => typeof value !== "string")) refuse();
  const label = `org.virki.validation=${owner}`;
  if (stage === "create-network") {
    const expected = ["network", "create", ...(kind === "migrator" ? ["--internal"] : []),
      "--label", label, network];
    if (!same(args, expected)) refuse();
    return;
  }

  const profiles = kind === "runtime" ? {
    "create-public": { name: containers[0], image: "production", network, command: ["npm", "run", "start", "--workspace", "@virki/public-site"], publish: "127.0.0.1::3000", detach: true },
    "create-issuer": { name: containers[1], image: "production", network, command: ["npm", "run", "start", "--workspace", "@virki/issuer"], alias: "oidc-issuer", detach: true },
    "create-hub": { name: containers[2], image: "production", network, command: [], publish: "127.0.0.1::3001", detach: true },
    "run-assertion": { name: containers[0], image: "production", network: "none", assertion: true, temporary: true },
  } : {
    "create-database": { name: containers[0], image: "postgres", network, alias: /^database-[a-f0-9-]{36}$/u, detach: true, volume: true },
    "run-deploy": { name: containers[1], image: "migrator", network, command: ["npm", "run", "prisma:migrate:deploy"], temporary: true },
    "run-status": { name: containers[2], image: "migrator", network, command: ["npm", "run", "prisma:migrate:status"], temporary: true },
  };
  const profile = profiles[stage];
  if (!profile || args[0] !== "run" || !profile.name) refuse();

  const values = new Map();
  const flags = new Set();
  let index = 1;
  for (; index < args.length; ) {
    const flag = args[index];
    if (!flag.startsWith("--")) break;
    if (BOOLEAN.has(flag)) {
      if (flags.has(flag)) refuse();
      flags.add(flag);
      index += 1;
    } else if (WITH_VALUE.has(flag)) {
      if (index + 1 >= args.length) refuse();
      const value = args[index + 1];
      if (flag !== "--env" && flag !== "--tmpfs" && values.has(flag)) refuse();
      const entries = values.get(flag) ?? [];
      entries.push(value);
      values.set(flag, entries);
      index += 2;
    } else refuse();
  }
  const list = (key) => values.get(key) ?? [];
  const single = (key) => list(key).length === 1 ? list(key)[0] : null;
  if (single("--name") !== profile.name || single("--network") !== profile.network ||
      single("--label") !== label || (flags.has("--detach") !== !!profile.detach) ||
      (flags.has("--rm") !== !!profile.temporary)) refuse();
  const privileged = profile.image !== "postgres";
  if (privileged && (!flags.has("--read-only") ||
      single("--cap-drop") !== "ALL" ||
      single("--security-opt") !== "no-new-privileges:true")) refuse();
  if (!privileged && (flags.has("--read-only") || list("--cap-drop").length ||
      list("--security-opt").length || list("--tmpfs").length)) refuse();
  if (list("--tmpfs").some((value) => !TMPFS.has(value)) ||
      single("--publish") !== (profile.publish ?? null) ||
      single("--entrypoint") !== (profile.assertion ? "node" : null)) refuse();
  if (profile.alias instanceof RegExp) {
    if (!profile.alias.test(single("--network-alias") ?? "")) refuse();
  } else if (single("--network-alias") !== (profile.alias ?? null)) refuse();
  if (profile.volume) {
    const mount = single("--volume") ?? "";
    if (mount !== ROLE_SETUP) refuse();
  } else if (list("--volume").length) refuse();
  const permittedEnvironment = ENV_NAMES[stage];
  const suppliedEnvironment = list("--env").map((value) => value.split("=", 1)[0]);
  if (suppliedEnvironment.some((name) => !permittedEnvironment?.has(name)) ||
      new Set(suppliedEnvironment).size !== suppliedEnvironment.length ||
      list("--env").some((value) => !/^[A-Z][A-Z0-9_]*(?:=.*)?$/u.test(value))) refuse();

  const image = args[index++];
  if (profile.image === "postgres" ? image !== POSTGRES :
      !new RegExp(`^virki-${profile.image === "production" ? "production" : "migrator"}-ci:[a-f0-9]{40}$`, "u").test(image ?? "")) refuse();
  const command = args.slice(index);
  if (profile.assertion) {
    if (command.length !== 2 || command[0] !== "-e" || !command[1]) refuse();
  } else if (!same(command, profile.command ?? [])) refuse();
}
