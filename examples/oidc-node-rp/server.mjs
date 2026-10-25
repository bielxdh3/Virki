import { readFile } from "node:fs/promises";
import { createServer } from "node:https";
import { createVirkiOidcClient, MemoryTransactionStore } from "@virki/oidc-node";
import { createRpHandler } from "./app.mjs";

// Demonstration ONLY: one process with in-memory transaction and session stores.
// Production must use an RP-owned distributed atomic flow store + session store.
const required = ["VIRKI_RP_CLIENT_ID", "VIRKI_RP_CLIENT_SECRET", "VIRKI_RP_REDIRECT_URI", "VIRKI_RP_TLS_KEY", "VIRKI_RP_TLS_CERT"];
if (required.some((name) => !process.env[name])) throw new Error("RP example configuration is incomplete.");

const issuer = process.env.VIRKI_RP_ISSUER ?? "https://portal.biel.dev.br";
const redirectUri = process.env.VIRKI_RP_REDIRECT_URI;
const client = await createVirkiOidcClient({
  issuer,
  clientId: process.env.VIRKI_RP_CLIENT_ID,
  clientSecret: process.env["VIRKI_RP_CLIENT_SECRET"],
  redirectUri,
  store: new MemoryTransactionStore()
});
const [key, cert] = await Promise.all([readFile(process.env.VIRKI_RP_TLS_KEY), readFile(process.env.VIRKI_RP_TLS_CERT)]);
const port = Number(process.env.VIRKI_RP_PORT ?? "3443");
if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) throw new Error("RP port is invalid.");
createServer({ key, cert, minVersion: "TLSv1.2" }, createRpHandler({ client, redirectUri }))
  .listen(port, "127.0.0.1", () => { console.log("Virki RP example ready on private loopback HTTPS."); });
