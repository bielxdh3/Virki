import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";
import { ConnectionInputError, isExactRedirectUriAllowed, projectConnectionConfigurationRevision, validateProjectConnectionInput, validateProjectLaunchUrl } from "./connection-policy";
import { ConnectionEditForm } from "../app/admin/connections/connection-edit-form";
import { ConnectionForm } from "../app/admin/connections/connection-form";

function renderForm(element: React.ReactElement): string {
  const testGlobals = globalThis as typeof globalThis & { React?: typeof React };
  const reactDescriptor = Object.getOwnPropertyDescriptor(globalThis, "React");
  testGlobals.React = React;
  try {
    return renderToStaticMarkup(element);
  } finally {
    if (reactDescriptor) Object.defineProperty(globalThis, "React", reactDescriptor);
    else Reflect.deleteProperty(globalThis, "React");
  }
}

function slugInputContract(html: string): { maxLength: number | null; pattern: RegExp } {
  const field = html.match(/<input\b(?=[^>]*\bname="slug")[^>]*>/u)?.[0];
  assert.ok(field, "connection form renders a slug input");
  const maxLength = field.match(/\bmaxlength="(\d+)"/iu)?.[1];
  const pattern = field.match(/\bpattern="([^"]+)"/u)?.[1];
  assert.ok(pattern, "slug input exposes its validation pattern");
  return { maxLength: maxLength ? Number(maxLength) : null, pattern: new RegExp(`^(?:${pattern})$`, "u") };
}

function namedInput(html: string, name: string): string {
  const field = html.match(new RegExp(`<input\\b(?=[^>]*\\bname="${name}")[^>]*>`, "u"))?.[0];
  assert.ok(field, `connection form renders the ${name} input`);
  return field;
}

test("redirect URI separator lines are ignored while invalid, duplicate and oversized entries still fail", () => {
  const input = { name: "Alpha", slug: "alpha", origin: "https://project.example.invalid", redirectUris: "\n https://project.example.invalid/callback \r\n \n" };
  assert.deepEqual(validateProjectConnectionInput(input).redirectUris, ["https://project.example.invalid/callback"]);
  for (const redirectUris of ["\n \n", "https://project.example.invalid/callback\n\nhttps://project.example.invalid/callback", "\ninvalid\n", `https://project.example.invalid/${"a".repeat(2048)}`, Array.from({ length: 11 }, (_, i) => `https://project.example.invalid/${i}`).join("\n")]) {
    assert.throws(() => validateProjectConnectionInput({ ...input, redirectUris }), ConnectionInputError);
  }
});

test("connection configuration revision binds each editable field and the connection identity", () => {
  const connection = {
    id: "connection-1",
    name: "Project Alpha",
    slug: "project-alpha",
    origin: "https://project.example.invalid",
    launchUrl: "https://project.example.invalid/start",
    redirectUris: ["https://project.example.invalid/auth/callback"],
  };
  const revision = projectConnectionConfigurationRevision(connection);
  assert.equal(projectConnectionConfigurationRevision({ ...connection }), revision);
  assert.match(revision, /^[A-Za-z0-9_-]{43}$/u);
  for (const change of [
    { id: "connection-2" },
    { name: "Project Beta" },
    { slug: "project-beta" },
    { origin: "https://other.example.invalid" },
    { launchUrl: null },
    { redirectUris: ["https://project.example.invalid/changed"] },
  ]) {
    assert.notEqual(projectConnectionConfigurationRevision({ ...connection, ...change }), revision);
  }
});

test("connection input accepts canonical origins and exact HTTPS redirect URIs", () => {
  assert.deepEqual(validateProjectConnectionInput({
    name: "Project Alpha",
    slug: "project-alpha",
    origin: "https://project.example.invalid",
    launchUrl: "",
    redirectUris: "https://project.example.invalid/auth/callback"
  }), {
    name: "Project Alpha",
    slug: "project-alpha",
    origin: "https://project.example.invalid",
    launchUrl: null,
    redirectUris: ["https://project.example.invalid/auth/callback"]
  });
});

test("connection launch URL remains on its canonical HTTPS origin", () => {
  assert.equal(validateProjectLaunchUrl("https://project.example.invalid", "https://project.example.invalid/start"), "https://project.example.invalid/start");
  for (const value of ["http://project.example.invalid/start", "https://other.example.invalid/start", "https://user:secret@project.example.invalid/start", "https://project.example.invalid/start?next=/admin", "https://project.example.invalid/start#fragment"]) {
    assert.throws(() => validateProjectLaunchUrl("https://project.example.invalid", value));
  }
});

test("redirect URI matching is exact and does not accept wildcard or origin-only matches", () => {
  const allowlist = ["https://project.example.invalid/auth/callback"];
  assert.equal(isExactRedirectUriAllowed(allowlist, "https://project.example.invalid/auth/callback"), true);
  assert.equal(isExactRedirectUriAllowed(allowlist, "https://project.example.invalid/other"), false);
  assert.throws(() => validateProjectConnectionInput({ name: "Alpha", slug: "alpha", origin: "https://project.example.invalid", redirectUris: "https://project.example.invalid/*" }));
});

test("connection validation rejects HTTP, credentials, fragments, and noncanonical URLs", () => {
  assert.throws(() => validateProjectConnectionInput({ name: "Alpha", slug: "alpha", origin: "http://project.example.invalid", redirectUris: "https://project.example.invalid/callback" }), ConnectionInputError);
  for (const redirectUri of [
    "http://project.example.invalid/callback",
    "https://user:password@project.example.invalid/callback",
    "https://project.example.invalid/callback#fragment",
    "https://project.example.invalid:443/callback"
  ]) {
    assert.throws(() => validateProjectConnectionInput({ name: "Alpha", slug: "alpha", origin: "https://project.example.invalid", redirectUris: redirectUri }));
  }
});

test("connection creation and edit forms match the server slug contract", () => {
  const longSlug = `alpha--${"b".repeat(57)}`;
  const paddedLongSlug = `  ${longSlug}  `;
  const editConnection = {
    id: "connection-1",
    name: "Alpha",
    slug: longSlug,
    origin: "https://project.example.invalid",
    launchUrl: null,
    redirectUris: ["https://project.example.invalid/callback"],
    configurationRevision: "revision-1",
  };
  const forms = [
    renderForm(React.createElement(ConnectionForm, { csrf: "test-csrf" })),
    renderForm(React.createElement(ConnectionEditForm, { csrf: "test-csrf", csrfFieldName: "csrfToken", connection: editConnection })),
  ];
  const slugs = [
    { slug: "a", accepted: true },
    { slug: "alpha--beta", accepted: true },
    { slug: "Alpha--Beta", accepted: true },
    { slug: "  Alpha--Beta  ", accepted: true },
    { slug: longSlug, accepted: true },
    { slug: paddedLongSlug, accepted: true },
    { slug: "-alpha", accepted: false },
    { slug: "alpha-", accepted: false },
    { slug: "K", accepted: false },
    { slug: "a".repeat(65), accepted: false },
  ];

  for (const html of forms) {
    const contract = slugInputContract(html);
    assert.match(namedInput(html, "slug"), /aria-describedby="[^"]+"/u, "slug normalization guidance is associated with the field");
    assert.match(html, /Até 64 letras, números e hífens\. Espaços externos são removidos e o valor é salvo em minúsculas\./u);
    for (const { slug, accepted } of slugs) {
      const acceptedByForm = (contract.maxLength === null || slug.length <= contract.maxLength) && contract.pattern.test(slug);
      const serverSlug = (() => {
        try {
          return validateProjectConnectionInput({ name: "Alpha", slug, origin: "https://project.example.invalid", redirectUris: "https://project.example.invalid/callback" }).slug;
        } catch (error) {
          if (error instanceof ConnectionInputError) return null;
          throw error;
        }
      })();
      const acceptedByServer = serverSlug !== null;
      assert.equal(acceptedByForm, accepted, `form accepts ${JSON.stringify(slug)} according to the server contract`);
      assert.equal(acceptedByServer, accepted, `server accepts ${JSON.stringify(slug)} according to the server contract`);
      if (accepted) assert.equal(serverSlug, slug.trim().toLowerCase(), `server canonicalizes ${JSON.stringify(slug)}`);
    }
  }
  assert.match(forms[1], new RegExp(`value="${longSlug}"`, "u"), "editing retains the existing long slug in the form");
});

test("new connection names reject C0, DEL, and C1 control characters before trimming", () => {
  const input = { name: "Alpha", slug: "alpha", origin: "https://project.example.invalid", redirectUris: "https://project.example.invalid/callback" };
  for (const name of ["Alpha\tProject", "Alpha\nProject", "Alpha\n", "Alpha\u007fProject", "Alpha\u0085Project", "Alpha\u009fProject"]) {
    assert.throws(() => validateProjectConnectionInput({ ...input, name }), ConnectionInputError, JSON.stringify(name));
  }
});

test("editing preserves an unchanged legacy control-character name but rejects a changed one", () => {
  const legacyName = "Legacy\nProject";
  const input = { name: "LegacyProject", slug: "legacy-project", origin: "https://project.example.invalid", redirectUris: "https://project.example.invalid/callback" };
  assert.equal(validateProjectConnectionInput(input, { existingName: legacyName, preserveExistingName: true }).name, legacyName);
  assert.equal(validateProjectConnectionInput({ ...input, name: legacyName }, { existingName: legacyName, preserveExistingName: true }).name, legacyName);
  assert.equal(validateProjectConnectionInput(input, { existingName: legacyName, preserveExistingName: false }).name, "LegacyProject");
  assert.throws(() => validateProjectConnectionInput({ ...input, name: "New\nProject" }, { existingName: legacyName, preserveExistingName: false }), ConnectionInputError);
});

test("new-name fields reject control characters while unchanged legacy edit names remain editable", () => {
  const createHtml = renderForm(React.createElement(ConnectionForm, { csrf: "test-csrf" }));
  const cleanEditHtml = renderForm(React.createElement(ConnectionEditForm, {
    csrf: "test-csrf",
    csrfFieldName: "csrfToken",
    connection: { id: "connection-clean", name: "Alpha", slug: "alpha", origin: "https://project.example.invalid", launchUrl: null, redirectUris: ["https://project.example.invalid/callback"], configurationRevision: "revision-clean" },
  }));
  const legacyEditHtml = renderForm(React.createElement(ConnectionEditForm, {
    csrf: "test-csrf",
    csrfFieldName: "csrfToken",
    connection: { id: "connection-legacy", name: "Legacy\nProject", slug: "legacy-project", origin: "https://project.example.invalid", launchUrl: null, redirectUris: ["https://project.example.invalid/callback"], configurationRevision: "revision-legacy" },
  }));

  for (const html of [createHtml, cleanEditHtml]) {
    const field = namedInput(html, "name");
    const pattern = field.match(/\bpattern="([^"]+)"/u)?.[1];
    assert.ok(pattern, "new names have a browser-side control-character check");
    const acceptsName = new RegExp(`^(?:${pattern})$`, "v");
    for (const name of ["Project Alpha", "Projeto 2", "Projeto\t2", "Projeto\n2", "Projeto\u007f2", "Projeto\u00852"]) {
      const acceptedByForm = acceptsName.test(name);
      const acceptedByServer = (() => {
        try {
          validateProjectConnectionInput({ name, slug: "alpha", origin: "https://project.example.invalid", redirectUris: "https://project.example.invalid/callback" });
          return true;
        } catch (error) {
          if (error instanceof ConnectionInputError) return false;
          throw error;
        }
      })();
      assert.equal(acceptedByForm, acceptedByServer, `name ${JSON.stringify(name)} follows the server contract`);
    }
  }

  assert.doesNotMatch(namedInput(legacyEditHtml, "name"), /\bpattern=/u, "the original legacy value is not blocked by browser validation");
  assert.match(legacyEditHtml, /type="checkbox" name="cleanLegacyName" value="true"/u);
  assert.match(legacyEditHtml, /Salvar o nome exibido e remover controles legados/u);
});

test("callback registration allows explicitly approved foreign origins but never arbitrary redirect targets", () => {
  const registration = validateProjectConnectionInput({
    name: "Federated project", slug: "federated", origin: "https://project.example.invalid",
    redirectUris: "https://project.example.invalid/callback\nhttps://login.partner.example.invalid/oidc/callback"
  });
  assert.deepEqual(registration.redirectUris, ["https://project.example.invalid/callback", "https://login.partner.example.invalid/oidc/callback"]);
  for (const candidate of ["https://login.partner.example.invalid/oidc/callback/", "https://evil.example.invalid/oidc/callback", "http://login.partner.example.invalid/oidc/callback", "https://project.example.invalid/callback?other=1"]) {
    assert.equal(isExactRedirectUriAllowed(registration.redirectUris, candidate), false, candidate);
  }
  assert.equal(isExactRedirectUriAllowed(registration.redirectUris, "https://login.partner.example.invalid/oidc/callback"), true);
});
