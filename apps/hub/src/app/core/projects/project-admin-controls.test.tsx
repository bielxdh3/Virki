import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import test from "node:test";

import {
  CoreProjectAdminControls,
  type CoreProjectAdminCopy
} from "./project-admin-controls";

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
