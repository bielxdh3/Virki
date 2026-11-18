// A deliberately tiny SMTP receiver for the disposable wire test. Its only
// listener is loopback, it requires TLS and test-only AUTH before accepting
// one exact envelope, and it never logs or persists a message.
import { createServer } from "node:net";
import { createSecureContext, TLSSocket } from "node:tls";

const MAX_MESSAGE_BYTES = 64 * 1024;
const MAX_LINE_BYTES = 4 * 1024;
const ALLOWED_LOOPBACK_PEERS = new Set(["127.0.0.1", "::ffff:127.0.0.1"]);

function codeFromMessage(data) {
  const boundary = data.indexOf("\r\n\r\n");
  if (boundary < 0) throw new Error("SMTP message has no body.");
  const headers = data.slice(0, boundary);
  const id = /^message-id:\s*(<[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+>)\s*$/imu.exec(headers)?.[1];
  if (!id) throw new Error("SMTP message has no valid Message-ID.");
  let body = data.slice(boundary + 4);
  if (/^content-transfer-encoding:\s*base64\s*$/imu.test(headers)) {
    body = Buffer.from(body.replace(/\s+/gu, ""), "base64").toString("utf8");
  } else if (/^content-transfer-encoding:\s*quoted-printable\s*$/imu.test(headers)) {
    body = Buffer.from(body.replace(/=\r\n/gu, "").replace(/=([0-9a-f]{2})/giu,
      (_, hex) => String.fromCharCode(Number.parseInt(hex, 16))), "binary").toString("utf8");
  }
  const codes = [...body.matchAll(/\b[0-9]{6}\b/gu)];
  if (codes.length !== 1) throw new Error("SMTP body must contain exactly one six-digit OTP.");
  return { code: codes[0][0], messageId: id };
}

export function assertLoopbackSmtpAddress(host, recipient, sender) {
  if (host !== "127.0.0.1" || !/^[a-z0-9._+-]+@integration\.invalid$/u.test(recipient) ||
      sender !== "wire-sender@integration.invalid") {
    throw new Error("SMTP test requires an exact loopback listener and synthetic mailboxes.");
  }
}

export async function createLoopbackSmtpSink({ certificate, privateKey, username, password, recipient }) {
  assertLoopbackSmtpAddress("127.0.0.1", recipient, "wire-sender@integration.invalid");
  if (username !== "smtp-wire@integration.invalid" ||
      typeof password !== "string" || !/^[a-f0-9]{64}$/u.test(password)) {
    throw new Error("SMTP test authentication must use a disposable credential.");
  }
  const context = createSecureContext({ cert: certificate, key: privateKey, minVersion: "TLSv1.2" });
  const sockets = new Set();
  let accepted = 0;
  let authenticated = 0;
  let upgraded = 0;
  let settled = false;
  let resolveReceipt;
  let rejectReceipt;
  const received = new Promise((resolve, reject) => {
    resolveReceipt = resolve;
    rejectReceipt = reject;
  });
  // An early setup failure may precede awaiting the receipt.
  void received.catch(() => {});
  const receiptTimeout = setTimeout(() => {
    if (!settled) {
      settled = true;
      rejectReceipt(new Error("Local SMTP receipt deadline exceeded."));
    }
  }, 30_000);

  const server = createServer((socket) => {
    sockets.add(socket);
    if (!ALLOWED_LOOPBACK_PEERS.has(socket.remoteAddress) || sockets.size > 2) {
      socket.destroy();
      return;
    }
    socket.setTimeout(15_000, () => socket.destroy());
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => {});
    let current = socket;
    let secure = false;
    let greeted = false;
    let authorized = false;
    let mailFrom = false;
    let rcptTo = false;
    let dataMode = false;
    let authStage = "";
    let authUser = "";
    let lineBuffer = "";
    let dataLines = [];
    let dataBytes = 0;

    const reply = (line) => current.write(line + "\r\n");
    const fail = () => { reply("554 Transaction rejected"); current.destroySoon?.(); };
    const checkAuth = (user, pass) => {
      if (user !== username || pass !== password) { reply("535 Authentication failed"); return; }
      authorized = true;
      authenticated += 1;
      reply("235 Authentication successful");
    };
    const decode = (encoded) => {
      if (!/^[A-Za-z0-9+/=]{1,1024}$/u.test(encoded)) return null;
      return Buffer.from(encoded, "base64").toString("utf8");
    };
    const handle = (line) => {
      if (dataMode) {
        if (line === ".") {
          dataMode = false;
          if (accepted !== 0) { fail(); return; }
          try {
            const message = codeFromMessage(dataLines.join("\r\n"));
            dataLines = [];
            accepted += 1;
            reply("250 Message accepted by local test sink");
            if (!settled) {
              settled = true;
              clearTimeout(receiptTimeout);
              resolveReceipt(message);
            }
          } catch { dataLines = []; fail(); }
          return;
        }
        dataBytes += Buffer.byteLength(line, "utf8") + 2;
        if (dataBytes > MAX_MESSAGE_BYTES) { dataLines = []; fail(); return; }
        dataLines.push(line.startsWith("..") ? line.slice(1) : line);
        return;
      }
      if (authStage) {
        const value = decode(line);
        if (value === null) { fail(); return; }
        if (authStage === "PLAIN") {
          authStage = "";
          const fields = value.split("\0");
          checkAuth(fields[fields.length - 2], fields.at(-1));
        } else if (authStage === "LOGIN_USER") {
          authUser = value;
          authStage = "LOGIN_PASSWORD";
          reply("334 UGFzc3dvcmQ6");
        } else {
          authStage = "";
          checkAuth(authUser, value);
          authUser = "";
        }
        return;
      }
      if (/^EHLO [^\r\n]+$/iu.test(line)) {
        greeted = true;
        reply(secure ? "250-local.test\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 65536" :
          "250-local.test\r\n250-STARTTLS\r\n250 SIZE 65536");
        return;
      }
      if (/^STARTTLS$/iu.test(line) && !secure && greeted) {
        greeted = false;
        socket.removeAllListeners("data");
        socket.write("220 Ready to start TLS\r\n", () => {
          const encrypted = new TLSSocket(socket, { isServer: true, secureContext: context });
          current = encrypted;
          encrypted.setTimeout(15_000, () => encrypted.destroy());
          encrypted.on("error", () => {});
          encrypted.on("secure", () => { secure = true; upgraded += 1; });
          encrypted.on("data", consume);
        });
        return;
      }
      if (!secure || !greeted) { reply("530 STARTTLS and EHLO required"); return; }
      const plain = /^AUTH PLAIN(?: ([A-Za-z0-9+/=]+))?$/iu.exec(line);
      if (plain) {
        if (!plain[1]) { authStage = "PLAIN"; reply("334 "); return; }
        const fields = decode(plain[1])?.split("\0") ?? [];
        checkAuth(fields[fields.length - 2], fields.at(-1));
        return;
      }
      if (/^AUTH LOGIN$/iu.test(line)) { authStage = "LOGIN_USER"; reply("334 VXNlcm5hbWU6"); return; }
      if (/^MAIL FROM:<wire-sender@integration\.invalid>(?: SIZE=\d+)?$/iu.test(line) && authorized) {
        mailFrom = true; reply("250 Sender accepted"); return;
      }
      if (line.toLowerCase() === `rcpt to:<${recipient}>` && mailFrom && !rcptTo) {
        rcptTo = true; reply("250 Recipient accepted"); return;
      }
      if (/^DATA$/iu.test(line) && rcptTo && accepted === 0) {
        dataMode = true; dataBytes = 0; dataLines = []; reply("354 End with <CRLF>.<CRLF>"); return;
      }
      if (/^QUIT$/iu.test(line)) { reply("221 Goodbye"); current.end(); return; }
      if (/^NOOP$/iu.test(line)) { reply("250 OK"); return; }
      fail();
    };
    function consume(chunk) {
      lineBuffer += chunk.toString("utf8");
      if (Buffer.byteLength(lineBuffer, "utf8") > MAX_MESSAGE_BYTES + MAX_LINE_BYTES) {
        current.destroy(); return;
      }
      for (let boundary = lineBuffer.indexOf("\r\n"); boundary !== -1; boundary = lineBuffer.indexOf("\r\n")) {
        const line = lineBuffer.slice(0, boundary);
        lineBuffer = lineBuffer.slice(boundary + 2);
        if (Buffer.byteLength(line, "utf8") > MAX_LINE_BYTES && !dataMode) { fail(); return; }
        handle(line);
      }
    }
    socket.on("data", consume);
    reply("220 localhost SMTP wire test ready");
  });

  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string" || address.address !== "127.0.0.1") {
      throw new Error("SMTP sink did not bind loopback.");
    }
    return {
      port: address.port,
      received,
      observations: () => ({ accepted, authenticated, upgraded }),
      async close() {
        clearTimeout(receiptTimeout);
        if (!settled) { settled = true; rejectReceipt(new Error("SMTP sink closed.")); }
        for (const socket of sockets) socket.destroy();
        await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
      }
    };
  } catch {
    clearTimeout(receiptTimeout);
    if (!settled) { settled = true; rejectReceipt(new Error("SMTP sink startup failed.")); }
    throw new Error("Local SMTP sink could not start.");
  }
}
