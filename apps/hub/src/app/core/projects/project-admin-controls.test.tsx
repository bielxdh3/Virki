import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";

import {
  CoreProjectAdminControls,
  type CoreProjectAdminCopy
} from "./project-admin-controls";
import {
  CORE_PROJECT_ACCESS_ELEVATION_SCOPE,
  CoreProjectAccessActionError,
  executeCoreProjectAccessAction,
  readCoreProjectAccessForm
} from "./project-access-action";

const copy: CoreProjectAdminCopy = {
  name: "Name",
  slug: "Slug",
  description: "Description",
  optional: "optional",
  visibility: "Visibility",
  status: "Status",
  save: "Save",
  archiveProject: "Archive project",
  archiveConfirm: "Confirm archive",
  noDelete: "Permanent deletion is unavailable.",
  public: "Public",
  internal: "Internal",
  sensitive: "Sensitive",
  planned: "Planned",
  reserved: "Reserved",
  active: "Active",
  paused: "Paused",
  viewer: "Viewer",
  editor: "Editor",
  owner: "Project owner (OWNER)",
  editDetails: "Edit metadata",
  accessDetails: "Manage access and project owner",
  selectUser: "Select user",
  accessLevel: "Project access level",
  ownerHelp: "OWNER defines this project's responsible owner.",
  accessElevationHelp: "Before applying or revoking access, activate PROJECT_OWNER_ACCESS_CHANGE, verify the emailed code, and return here.",
  accessElevationLink: "Open Administrative security",
  applyAccess: "Apply access",
  currentAccess: "Current access",
  noAccess: "No explicit access.",
  inactiveUser: "Inactive",
  activeUser: "Active",
  revokeAccess: "Revoke",
  accessLimit: "Up to 100 access rows.",
  archiveDetails: "Archive area"
};

const project = {
  id: "project-id",
  name: "Project",
  slug: "project",
  description: null,
  visibility: "INTERNAL",
  status: "ACTIVE",
  accesses: []
};

const activeUsers = [
  {
    id: "member-id",
    email: "member@example.invalid",
    displayName: null,
    role: "MEMBER"
  }
];

function getAccessForm(markup: string): string {
  const form = markup.match(
    /<form class="compact-form core-project-access-form"[\s\S]*?<\/form>/
  )?.[0];

  assert.ok(form, "the project access form should render");
  return form;
}

test("global OWNER access form submits the selected project OWNER level", () => {
  const markup = renderToStaticMarkup(createElement(CoreProjectAdminControls, {
    project,
    activeUsers,
    actorRole: "OWNER",
    copy,
    returnToDetail: true
  }));
  const accessForm = getAccessForm(markup);

  assert.match(accessForm, /name="userId"/);
  assert.match(accessForm, /value="member-id"/);
  assert.match(accessForm, /name="accessLevel"/);
  assert.match(accessForm, /<option value="OWNER">Project owner \(OWNER\)<\/option>/);
  assert.match(accessForm, /OWNER defines this project(?:'|&#x27;)s responsible owner/);
  assert.match(markup, /Before applying or revoking access, activate PROJECT_OWNER_ACCESS_CHANGE/);
  assert.match(markup, /href="\/core\/security\/admin\?scope=PROJECT_OWNER_ACCESS_CHANGE#admin-elevation-form">Open Administrative security<\/a>/);
});

test("global ADMIN access form cannot submit a project OWNER level", () => {
  const markup = renderToStaticMarkup(createElement(CoreProjectAdminControls, {
    project,
    activeUsers,
    actorRole: "ADMIN",
    copy
  }));
  const accessForm = getAccessForm(markup);

  assert.doesNotMatch(accessForm, /<option value="OWNER">/);
  assert.match(accessForm, /name="accessLevel"/);
});

function accessFormData(overrides: Record<string, string> = {}): FormData {
  const formData = new FormData();
  formData.set("projectId", overrides.projectId ?? "project-id");
  formData.set("userId", overrides.userId ?? "member-id");
  formData.set("accessLevel", overrides.accessLevel ?? "OWNER");
  return formData;
}

test("the browser access form passes its canonical member and role to the guarded action", async () => {
  const calls: Array<unknown[]> = [];
  const result = await executeCoreProjectAccessAction(
    accessFormData(),
    { id: "owner-id", role: "OWNER" },
    "session-id",
    {
      requireElevation: async (...args) => { calls.push(args); },
      setAccess: async (...args) => {
        calls.push(args);
        return { kind: "granted", accessId: "access-id" };
      }
    }
  );

  assert.deepEqual(result.input, {
    projectId: "project-id",
    userId: "member-id",
    accessLevel: "OWNER"
  });
  assert.deepEqual(calls, [
    ["owner-id", "session-id", CORE_PROJECT_ACCESS_ELEVATION_SCOPE],
    [{ id: "owner-id", role: "OWNER" }, "project-id", "member-id", "OWNER"]
  ]);
});

test("missing or expired elevation rejects before mutation and rejected targets cannot report success", async () => {
  let mutationCalls = 0;

  await assert.rejects(
    executeCoreProjectAccessAction(accessFormData(), { id: "owner-id", role: "OWNER" }, "session-id", {
      requireElevation: async () => { throw new Error("elevation unavailable"); },
      setAccess: async () => {
        mutationCalls += 1;
        return { kind: "granted", accessId: "access-id" };
      }
    }),
    (error) => error instanceof CoreProjectAccessActionError && error.stage === "elevation"
  );
  assert.equal(mutationCalls, 0);

  assert.equal(readCoreProjectAccessForm(accessFormData({ userId: "" })), null);

  for (const rejection of ["expired elevation", "nonexistent target", "unauthorized actor", "last active owner"]) {
    await assert.rejects(
      executeCoreProjectAccessAction(accessFormData(), { id: "owner-id", role: "OWNER" }, "session-id", {
        requireElevation: async () => {},
        setAccess: async () => { throw new Error(rejection); }
      }),
      (error) => error instanceof CoreProjectAccessActionError && error.stage === "mutation"
    );
  }
});
