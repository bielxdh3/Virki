/**
 * Read-only external acceptance probe for the native ADMIN ingress.
 * This runs without credentials, does not follow redirects, and never changes Cloudflare or production state.
 * An Access interstitial cannot be mistaken for Virki's own login page.
 */
import { pathToFileURL } from "node:url";
import { isCanonicalNativeAdminRedirect } from "./lib/native-hub-login-redirect.mjs";

export async function checkNativeHubIngress(target, fetcher = fetch) {
  let origin;
  try {
    const parsed = new URL(target);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash || parsed.port) {
      throw new Error("not a clean HTTPS origin");
    }
    origin = parsed.origin;
  } catch {
    throw new Error("An unadorned HTTPS origin is required (no paths, credentials, ports, or query parameters).");
  }

  const probes = [
    { path: "/login" },
    { path: "/recover" },
    { path: "/admin/accounts" },
    { path: "/admin/audit" },
    { path: "/admin/security" },
    { path: "/admin/access" },
    { path: "/admin/connections" },
    { path: "/admin/accounts", forgedCookie: true },
    { path: "/login", forgedAccessJwt: true },
    { path: "/admin/accounts", forgedAccessJwt: true }
  ];
  for (const { path, forgedCookie, forgedAccessJwt } of probes) {
    const label = forgedCookie ? `${path} (forged cookie)` : forgedAccessJwt ? `${path} (forged Access JWT)` : path;
    const response = await fetcher(`${origin}${path}`, {
      method: "GET",
      redirect: "manual",
      headers: { Accept: "text/html", "Cache-Control": "no-cache", ...(forgedCookie ? { Cookie: "__Host-virki_session=forged" } : {}),
        ...(forgedAccessJwt ? { "cf-access-jwt-assertion": "forged" } : {}) },
      signal: AbortSignal.timeout(10000)
    });
    const privileged = path.startsWith("/admin/");
    if (!privileged && response.status !== 200) {
      throw new Error(`${label}: HTTP ${response.status}; native login/recovery is not publicly reachable without an external authentication gate.`);
    }
    if (privileged && response.status !== 307) {
      throw new Error(`${label}: HTTP ${response.status}; unauthenticated ADMIN must redirect to Virki login.`);
    }
    if (!response.headers.get("x-virki-request-id") || !response.headers.get("content-security-policy")) {
      throw new Error(`${label}: missing Virki request identity/security headers; response may come from Cloudflare Access or another gateway.`);
    }
    if (!hasRequiredSecurityHeaders(response.headers)) {
      throw new Error(`${label}: missing native ingress security headers (HSTS, no-store, clickjacking and CSP controls).`);
    }
    if (!privileged) {
      const markup = activeHtml(await response.text());
      const isLogin = path === "/login";
      const hasNativeForm = isLogin
        ? markup.includes('<h1 id="login-title">Entrar</h1>') && hasNativeLoginForm(markup)
        : markup.includes('<h1 id="recover-title">Recuperar acesso administrativo</h1>') && hasNativeAdminRecoveryForms(markup);
      if (!hasNativeForm) {
        throw new Error(`${label}: Virki's native login/recovery form or correctly scoped CSRF field is missing.`);
      }
    }
    if (privileged) {
      const location = response.headers.get("location");
      if (!isCanonicalNativeAdminRedirect(location, origin, path)) {
        throw new Error(`${label}: redirect is not the canonical Virki login; possible external identity gate.`);
      }
    }
  }
  return { origin, checked: probes.map(({ path, forgedCookie, forgedAccessJwt }) => forgedCookie
    ? `${path} (forged cookie)` : forgedAccessJwt ? `${path} (forged Access JWT)` : path) };
}

function activeHtml(markup) {
  // A bounded structural projection, not a browser or a CSRF verifier.
  // Recognize entire HTML start tags with quote-aware boundaries first:
  // markup inside a data-fixture="...<form>..." attribute is never a DOM form.
  const inert = new Set(["script", "style", "template", "noscript", "textarea",
    "title", "xmp", "iframe", "noembed", "noframes", "plaintext"]);
  const hidden = [];
  const visible = [];
  let cursor = 0;
  let formOpen = false;
  const disabledAncestors = [];
  while (cursor < markup.length) {
    const open = markup.indexOf("<", cursor);
    if (open < 0) {
      if (hidden.length === 0) visible.push(markup.slice(cursor));
      break;
    }
    if (hidden.length === 0) visible.push(markup.slice(cursor, open));
    if (markup.startsWith("<!--", open)) {
      const end = markup.indexOf("-->", open + 4);
      if (end < 0) return "";
      cursor = end + 3;
      continue;
    }
    const nameMatch = /^<(\/?)(([A-Za-z][A-Za-z0-9:-]*))(?=[\s/>])/u.exec(markup.slice(open, open + 100));
    if (!nameMatch) {
      if (hidden.length === 0) visible.push("<");
      cursor = open + 1;
      continue;
    }
    const closing = nameMatch[1] === "/";
    const name = nameMatch[2].toLowerCase();
    let end = open + nameMatch[0].length;
    let quote = null;
    for (; end < markup.length; end += 1) {
      const character = markup[end];
      if (quote) { if (character === quote) quote = null; }
      else if (character === '"' || character === "'") quote = character;
      else if (character === ">") break;
    }
    if (end >= markup.length) return "";
    const tag = markup.slice(open, end + 1);
    cursor = end + 1;
    if (hidden.length > 0) {
      if (closing && hidden[hidden.length - 1] === name) hidden.pop();
      else if (!closing && hidden[hidden.length - 1] === "template" && inert.has(name)) hidden.push(name);
      continue;
    }
    if (inert.has(name)) {
      if (!closing) hidden.push(name);
      continue;
    }
    if (closing) {
      if (name === "form") {
        if (!formOpen) return "";
        formOpen = false;
      }
      if (name === "fieldset") {
        if (!disabledAncestors.length) return "";
        disabledAncestors.pop();
      }
      visible.push("</" + name + ">");
      continue;
    }
    if (name === "fieldset") {
      const attributes = tagAttributes(tag);
      if (!attributes) return "";
      disabledAncestors.push(disabledAncestors.includes(true) || attributes.has("disabled"));
    }
    if (name === "form") {
      if (formOpen || disabledAncestors.includes(true) || /\/\s*>$/u.test(tag)) return "";
      formOpen = true;
    }
    // Keep only attributes relevant to the form contract. Values are encoded
    // so quoted pseudo-tags cannot reappear in the normalized HTML projection.
    const accepted = name === "form" ? ["action", "method"] :
      name === "input" ? ["name", "value", "type", "disabled", "form", "readonly"] :
        name === "fieldset" ? ["disabled"] : name === "h1" ? ["id"] : [];
    const attributes = accepted.length ? tagAttributes(tag) : null;
    if (accepted.length && !attributes) return "";
    const fields = accepted.flatMap((attribute) => {
      const value = attributes?.get(attribute);
      if (value === undefined) return [];
      if (value === null) return [" " + attribute];
      const escaped = value.replaceAll("&", "&amp;").replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;").replaceAll('"', "&quot;");
      return [" " + attribute + '="' + escaped + '"'];
    });
    visible.push("<" + name + fields.join("") + ">");
  }
  return hidden.length || formOpen || disabledAncestors.length ? "" : visible.join("");
}

function hasRequiredSecurityHeaders(headers) {
  const csp = new Map();
  for (const directive of (headers.get("content-security-policy") ?? "").split(";").map((value) => value.trim().toLowerCase()).filter(Boolean)) {
    const name = directive.split(/\s+/u, 1)[0];
    // Browsers use the first occurrence of duplicated directives; don't accept
    // a later safe value when an earlier effective one is permissive.
    if (csp.has(name)) return false;
    csp.set(name, directive);
  }
  const hstsMaxAges = (headers.get("strict-transport-security") ?? "").split(";").map((value) => value.trim())
    .filter((value) => /^max-age\s*=/iu.test(value));
  const hstsAge = hstsMaxAges.length === 1 ? /^max-age=(\d+)$/iu.exec(hstsMaxAges[0]) : null;
  return csp.get("frame-ancestors") === "frame-ancestors 'none'" && csp.get("base-uri") === "base-uri 'none'" &&
    (csp.get("object-src") === "object-src 'none'" || (!csp.has("object-src") && csp.get("default-src") === "default-src 'none'")) &&
    // Cloudflare's independently observed staging HTTPS policy currently sets 30 days.
    Number(hstsAge?.[1]) >= 2_592_000 &&
    (headers.get("cache-control") ?? "").split(",").some((directive) => directive.trim().toLowerCase() === "no-store") &&
    headers.get("x-frame-options") === "DENY" && headers.get("x-content-type-options") === "nosniff";
}

function hasScopedCsrfField(markup, scope) {
  const encodedScope = Buffer.from(scope, "utf8").toString("base64url");
  return usableInputs(markup).some((attributes) => {
    if (attributes.get("name") !== "csrfToken") return false;
    const value = attributes.get("value");
    if (!value) return false;
    const parts = value.split(".");
    return parts.length === 6 && parts[0] === "v2" && /^[a-f0-9]{64}$/u.test(parts[1]) &&
      /^[0-9]{13}$/u.test(parts[2]) && /^[A-Za-z0-9_-]{32}$/u.test(parts[3]) &&
      parts[4] === encodedScope && /^[A-Za-z0-9_-]{43}$/u.test(parts[5]);
  });
}

// Match HTML attributes by their complete name, not a word boundary within
// data-name/data-action (or a quoted attribute value). This intentionally
// remains a structural acceptance probe, not a browser/CSRF parser.
function tagAttributes(tag) {
  const opening = /^<[a-z][a-z0-9-]*\b/iu.exec(tag);
  if (!opening) return null;
  const attributes = new Map();
  let index = opening[0].length;
  while (index < tag.length) {
    while (/\s/u.test(tag[index] ?? "")) index += 1;
    if (tag[index] === ">" || (tag[index] === "/" && tag[index + 1] === ">")) return attributes;
    const start = index;
    while (index < tag.length && !/[\s=/>]/u.test(tag[index])) index += 1;
    if (index === start) return null;
    const name = tag.slice(start, index).toLowerCase();
    while (/\s/u.test(tag[index] ?? "")) index += 1;
    let value = null;
    if (tag[index] === "=") {
      index += 1;
      while (/\s/u.test(tag[index] ?? "")) index += 1;
      const quote = tag[index] === '"' || tag[index] === "'" ? tag[index++] : null;
      const valueStart = index;
      if (quote) {
        index = tag.indexOf(quote, index);
        if (index < 0) return null;
        value = tag.slice(valueStart, index);
        index += 1;
      } else {
        while (index < tag.length && !/[\s>]/u.test(tag[index])) index += 1;
        if (index === valueStart) return null;
        value = tag.slice(valueStart, index);
      }
    }
    if (attributes.has(name)) return null;
    attributes.set(name, value);
  }
  return null;
}

function usableInputs(formBody) {
  // Disabled controls and those assigned to a different form are not
  // submitted with this POST. Disabled fieldsets also suppress their
  // descendants. Fail closed on ambiguous form ownership.
  const fieldsetDisabled = [];
  const inputs = [];
  for (const [tag] of formBody.matchAll(/<\/?fieldset(?=[\s/>])[^>]*>|<input(?=[\s/>])[^>]*>/giu)) {
    if (/^<fieldset(?=[\s/>])/iu.test(tag)) {
      const attributes = tagAttributes(tag);
      fieldsetDisabled.push(fieldsetDisabled.includes(true) || attributes?.has("disabled") === true);
    } else if (/^<\/fieldset(?=[\s/>])/iu.test(tag)) {
      if (!fieldsetDisabled.length) return [];
      fieldsetDisabled.pop();
    } else {
      const attributes = tagAttributes(tag);
      if (!attributes || attributes.has("disabled") || attributes.has("form") || fieldsetDisabled.includes(true)) continue;
      const type = (attributes.get("type") ?? "text")?.toLowerCase();
      if (["button", "submit", "reset", "image", "file", "checkbox", "radio"].includes(type)) continue;
      inputs.push(attributes);
    }
  }
  return fieldsetDisabled.length === 0 ? inputs : [];
}

function formTags(markup) {
  // A bounded structural acceptance check, not a browser HTML parser or a
  // cryptographic CSRF validation. Never combine unrelated forms or values
  // in embedded Next.js scripts to fabricate a successful entrypoint.
  return [...markup.matchAll(/(<form(?=[\s/>])[^>]*>)([\s\S]*?)<\/form\s*>/giu)]
    .map((match) => ({ open: match[1], body: match[2] }));
}

function hasInput(formBody, name, editable = false) {
  return usableInputs(formBody).some((attributes) => {
    if (attributes.get("name") !== name) return false;
    if (!editable) return true;
    const type = (attributes.get("type") ?? "text")?.toLowerCase();
    return !attributes.has("readonly") && !["hidden", "passwordless"].includes(type);
  });
}

function hasMethodSelector(formBody) {
  // The first recovery form is a method-choice UI, not the action POST itself:
  // unavailable methods can have a disabled radio while the separate email
  // server-action form remains operable. It still needs a real named control.
  return [...formBody.matchAll(/<input(?=[\s/>])[^>]*>/giu)].some(([input]) => {
    const attributes = tagAttributes(input);
    return attributes?.get("name") === "method" && !attributes.has("form");
  });
}

function hasNativeLoginForm(markup) {
  return formTags(markup).some(({ open, body }) =>
    tagAttributes(open)?.get("action") === "/api/login" && tagAttributes(open)?.get("method")?.toLowerCase() === "post" &&
    hasInput(body, "email", true) && hasInput(body, "password", true) &&
    hasScopedCsrfField(body, "login"));
}

function hasNativeAdminRecoveryForms(markup) {
  const forms = formTags(markup);
  // The React progressive recovery page has a method-selection UI form and a
  // separate POST server-action form for legacy email recovery. A single GET
  // placeholder (even with matching labels and a forged token) is insufficient.
  const methodSelectorIndex = forms.findIndex(({ body }) =>
    hasInput(body, "email", true) && hasMethodSelector(body) &&
    hasScopedCsrfField(body, "recovery-admin-request"));
  const serverActionPost = forms.some(({ open, body }, index) =>
    index !== methodSelectorIndex && tagAttributes(open)?.get("method")?.toLowerCase() === "post" && hasInput(body, "email", true) &&
    usableInputs(body).some((attributes) =>
      /^\$ACTION_ID_[a-f0-9]{32,64}$/iu.test(attributes.get("name") ?? "")) &&
    hasScopedCsrfField(body, "recovery-admin-request"));
  return methodSelectorIndex >= 0 && serverActionPost;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const target = process.argv[2];
  checkNativeHubIngress(target).then(
    ({ origin }) => console.log(`PASS: anonymous native ingress probe on ${origin}; this does not attest Cloudflare account configuration, MFA, or production cutover.`),
    (error) => { console.error(`NO-GO native ingress: ${error.message}`); process.exitCode = 1; }
  );
}
