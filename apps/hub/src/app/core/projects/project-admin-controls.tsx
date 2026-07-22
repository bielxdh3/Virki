import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";

import {
  archiveCoreProject,
  revokeCoreProjectAccess,
  setCoreProjectAccess,
  updateCoreProject
} from "./actions";
import { canShowCoreProjectMutationControls } from "./detail-policy";
import { isCoreAdministrator } from "../authorization";

export type CoreProjectAdminCopy = {
  name: string;
  slug: string;
  description: string;
  optional: string;
  visibility: string;
  status: string;
  save: string;
  archiveProject: string;
  archiveConfirm: string;
  noDelete: string;
  public: string;
  internal: string;
  sensitive: string;
  planned: string;
  reserved: string;
  active: string;
  paused: string;
  viewer: string;
  editor: string;
  owner: string;
  editDetails: string;
  accessDetails: string;
  selectUser: string;
  accessLevel: string;
  applyAccess: string;
  currentAccess: string;
  noAccess: string;
  inactiveUser: string;
  activeUser: string;
  revokeAccess: string;
  accessLimit: string;
  archiveDetails: string;
};

type Project = {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  visibility: string;
  status: string;
  accesses: Array<{
    accessLevel: string;
    user: {
      id: string;
      email: string;
      displayName: string | null;
      role: string;
      isActive: boolean;
    };
  }>;
};

type ActiveUser = {
  id: string;
  email: string;
  displayName: string | null;
  role: string;
};

const visibilityValues = ["PUBLIC", "INTERNAL", "SENSITIVE"] as const;
const statusValues = ["PLANNED", "RESERVED", "ACTIVE", "PAUSED"] as const;

function visibilityLabel(value: string, copy: CoreProjectAdminCopy): string {
  return ({ PUBLIC: copy.public, INTERNAL: copy.internal, SENSITIVE: copy.sensitive })[value] ?? value;
}

function statusLabel(value: string, copy: CoreProjectAdminCopy): string {
  return ({
    PLANNED: copy.planned,
    RESERVED: copy.reserved,
    ACTIVE: copy.active,
    PAUSED: copy.paused
  })[value] ?? value;
}

function accessLabel(value: string, copy: CoreProjectAdminCopy): string {
  return ({ VIEWER: copy.viewer, EDITOR: copy.editor, OWNER: copy.owner })[value] ?? value;
}

export function CoreProjectAdminControls({
  project,
  activeUsers,
  actorRole,
  copy,
  returnToDetail = false
}: {
  project: Project;
  activeUsers: ActiveUser[];
  actorRole: string;
  copy: CoreProjectAdminCopy;
  returnToDetail?: boolean;
}) {
  if (!canShowCoreProjectMutationControls(isCoreAdministrator(actorRole), project.status)) {
    return null;
  }

  const csrfToken = createCsrfToken();
  const returnField = returnToDetail ? (
    <input type="hidden" name="returnTo" value="detail" />
  ) : null;

  return (
    <div className="core-project-actions" aria-label={`${copy.editDetails}: ${project.name}`}>
      <details className="admin-drawer core-project-drawer">
        <summary>{copy.editDetails}</summary>
        <form className="compact-form core-project-form" action={updateCoreProject}>
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
          <input type="hidden" name="projectId" value={project.id} />
          {returnField}
          <label>
            <span>{copy.name}</span>
            <input name="name" required minLength={2} maxLength={80} defaultValue={project.name} />
          </label>
          <label>
            <span>{copy.slug}</span>
            <input
              name="slug"
              required
              minLength={3}
              maxLength={64}
              pattern="[a-z0-9]+(?:-[a-z0-9]+)*"
              defaultValue={project.slug}
            />
          </label>
          <label className="core-project-description-field">
            <span>{copy.description} ({copy.optional})</span>
            <textarea name="description" maxLength={500} rows={3} defaultValue={project.description ?? ""} />
          </label>
          <label>
            <span>{copy.visibility}</span>
            <select name="visibility" defaultValue={project.visibility}>
              {visibilityValues.map((value) => (
                <option key={value} value={value}>{visibilityLabel(value, copy)}</option>
              ))}
            </select>
          </label>
          <label>
            <span>{copy.status}</span>
            <select name="status" defaultValue={project.status}>
              {statusValues.map((value) => (
                <option key={value} value={value}>{statusLabel(value, copy)}</option>
              ))}
            </select>
          </label>
          <div className="button-row core-project-form-actions">
            <button className="button-primary" type="submit">{copy.save}</button>
          </div>
        </form>
      </details>

      <details className="admin-drawer core-project-drawer core-project-access-drawer">
        <summary>{copy.accessDetails}</summary>
        <div className="core-project-access-panel">
          <form className="compact-form core-project-access-form" action={setCoreProjectAccess}>
            <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
            <input type="hidden" name="projectId" value={project.id} />
            {returnField}
            <label>
              <span>{copy.selectUser}</span>
              <select name="userId" required defaultValue="">
                <option value="" disabled>{copy.selectUser}</option>
                {activeUsers
                  .filter((user) =>
                    actorRole === "OWNER" ||
                    !project.accesses.some(
                      (access) => access.user.id === user.id && access.accessLevel === "OWNER"
                    )
                  )
                  .map((user) => (
                    <option key={user.id} value={user.id}>
                      {user.displayName ? `${user.displayName} - ` : ""}
                      {user.email} ({user.role})
                    </option>
                  ))}
              </select>
            </label>
            <label>
              <span>{copy.accessLevel}</span>
              <select name="accessLevel" defaultValue="VIEWER">
                <option value="VIEWER">{copy.viewer}</option>
                <option value="EDITOR">{copy.editor}</option>
                {actorRole === "OWNER" ? <option value="OWNER">{copy.owner}</option> : null}
              </select>
            </label>
            <div className="button-row core-project-form-actions">
              <button className="button-primary" type="submit">{copy.applyAccess}</button>
            </div>
          </form>

          <div className="core-project-access-list" aria-label={copy.currentAccess}>
            <div className="core-project-access-heading">
              <strong>{copy.currentAccess}</strong>
              <span>{project.accesses.length} / 100</span>
            </div>
            {project.accesses.length === 0 ? (
              <p className="core-project-access-empty">{copy.noAccess}</p>
            ) : (
              project.accesses.map((access) => (
                <div className="core-project-access-row" key={access.user.id}>
                  <div>
                    <strong>{access.user.displayName ?? access.user.email}</strong>
                    <span>
                      {access.user.displayName ? `${access.user.email} / ` : ""}
                      {accessLabel(access.accessLevel, copy)} / {access.user.isActive ? copy.activeUser : copy.inactiveUser}
                    </span>
                  </div>
                  {actorRole === "OWNER" || access.accessLevel !== "OWNER" ? (
                    <form action={revokeCoreProjectAccess}>
                      <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                      <input type="hidden" name="projectId" value={project.id} />
                      <input type="hidden" name="userId" value={access.user.id} />
                      {returnField}
                      <button className="button-danger" type="submit">{copy.revokeAccess}</button>
                    </form>
                  ) : null}
                </div>
              ))
            )}
            <small>{copy.accessLimit}</small>
          </div>
        </div>
      </details>

      <details className="admin-drawer core-project-drawer core-project-archive-drawer">
        <summary>{copy.archiveDetails}</summary>
        <form className="core-project-archive-form" action={archiveCoreProject}>
          <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
          <input type="hidden" name="projectId" value={project.id} />
          {returnField}
          <p>{copy.noDelete}</p>
          <label className="checkbox-line">
            <input type="checkbox" name="confirmArchive" value="yes" required />
            <span>{copy.archiveConfirm}</span>
          </label>
          <div className="button-row">
            <button className="button-danger" type="submit">{copy.archiveProject}</button>
          </div>
        </form>
      </details>
    </div>
  );
}
