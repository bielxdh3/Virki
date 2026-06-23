import { createCsrfToken, CSRF_FORM_FIELD_NAME } from "@bielos/auth/csrf";
import { moduleCatalog } from "@bielos/ui";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../lib/cloudflare-access";
import { getCurrentSession } from "../lib/auth";

export const dynamic = "force-dynamic";

const moduleCards = [
  {
    name: "BielOS Core",
    shortName: "OS",
    description: "Main hub interface, session boundary, and module overview.",
    status: "Active",
    sensitivity: "internal"
  },
  ...moduleCatalog.map((module) => ({
    name: module.name,
    shortName: module.shortName,
    description: module.description,
    status: module.status,
    sensitivity: module.sensitivity
  }))
];

const deploymentStatus = [
  { label: "Public site", value: "Available" },
  { label: "Hub", value: "Protected" },
  { label: "Tunnel", value: "Managed" },
  { label: "Module data", value: "Not mounted" }
];

const securityLayers = [
  {
    name: "Cloudflare Access",
    description: "External access check before the hub is reached.",
    state: "First"
  },
  {
    name: "BielOS Internal Auth",
    description: "Local application session for the private hub.",
    state: "Second"
  }
];

export default async function HubDashboardPage() {
  const requestHeaders = await headers();
  const accessResult = await validateHubCloudflareAccess(requestHeaders, "hub-dashboard");

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  const reservedModules = moduleCards.filter((module) => module.status !== "Active");
  const csrfToken = createCsrfToken();

  return (
    <main className="hub-shell">
      <aside className="os-dock" aria-label="BielOS navigation">
        <div className="dock-identity">
          <img src="/hub-mark.svg" alt="" />
          <div>
            <strong>BielOS</strong>
            <span>Private Hub</span>
          </div>
        </div>

        <nav className="dock-nav" aria-label="Primary">
          <a href="#overview" aria-label="View overview">
            <span aria-hidden="true">01</span>
            <strong>Overview</strong>
          </a>
          <a href="#modules" aria-label="View modules">
            <span aria-hidden="true">02</span>
            <strong>Modules</strong>
          </a>
          <a href="#security" aria-label="View security layers">
            <span aria-hidden="true">03</span>
            <strong>Security</strong>
          </a>
          <a href="#ops" aria-label="View operations">
            <span aria-hidden="true">04</span>
            <strong>Ops</strong>
          </a>
        </nav>

        <div className="dock-footer">
          <span>Status</span>
          <strong>Running</strong>
        </div>
      </aside>

      <section className="hub-workspace">
        <header className="top-statusbar">
          <div className="statusbar-left">
            <span className="status-dot" aria-hidden="true" />
            <span>hub.biel.dev.br</span>
            <span>Protected</span>
          </div>
          <form action="/api/logout" method="post">
            <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
            <button className="icon-command" type="submit" aria-label="Log out">
              <span>Log out</span>
            </button>
          </form>
        </header>

        <section className="identity-panel anchor-section" id="overview" aria-label="System identity">
          <div>
            <p className="eyebrow">BielOS Hub</p>
            <h1>Workspace</h1>
            <p>
              Personal workspace for projects, tools, archives, automation, and technical labs.
              Modules stay reserved until they are implemented.
            </p>
          </div>
          <div className="identity-meter" aria-label="Core readiness">
            <span>Session</span>
            <strong>Active</strong>
          </div>
        </section>

        <div className="section-heading">
          <div>
            <p className="eyebrow">Overview</p>
            <h2>Session, security, and local stack</h2>
          </div>
          <span>Core only</span>
        </div>

        <section className="dashboard-grid" aria-label="Hub dashboard">
          <article className="panel session-panel">
            <div className="panel-title">
              <span>Session</span>
              <strong className="status-pill is-active">Unlocked</strong>
            </div>
            <div className="session-avatar" aria-hidden="true">
              {session.user.email.slice(0, 2).toUpperCase()}
            </div>
            <dl className="detail-list">
              <div>
                <dt>Identity</dt>
                <dd>{session.user.email}</dd>
              </div>
              <div>
                <dt>Role</dt>
                <dd>{session.user.role}</dd>
              </div>
            </dl>
          </article>

          <article className="panel deployment-panel anchor-section" id="ops">
            <div className="panel-title">
              <span>Operations</span>
              <strong className="status-pill">Local stack</strong>
            </div>
            <div className="status-list">
              {deploymentStatus.map((item) => (
                <div key={item.label}>
                  <span>{item.label}</span>
                  <strong>{item.value}</strong>
                </div>
              ))}
            </div>
          </article>

          <article className="panel security-panel anchor-section" id="security">
            <div className="panel-title">
              <span>Security</span>
              <strong className="status-pill is-guarded">Two layers</strong>
            </div>
            <div className="layer-stack">
              {securityLayers.map((layer) => (
                <div className="layer-item" key={layer.name}>
                  <span>{layer.state}</span>
                  <div>
                    <strong>{layer.name}</strong>
                    <p>{layer.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </article>

          <article className="panel quick-actions">
            <div className="panel-title">
              <span>Quick Actions</span>
              <strong className="status-pill">Safe</strong>
            </div>
            <div className="action-stack">
              <a href="#modules">View modules</a>
              <a href="#ops">View deployment status</a>
              <form action="/api/logout" method="post">
                <input type="hidden" name={CSRF_FORM_FIELD_NAME} value={csrfToken} />
                <button type="submit">Log out</button>
              </form>
            </div>
          </article>
        </section>

        <section className="module-window anchor-section" id="modules" aria-label="Module grid">
          <div className="window-titlebar">
            <div>
              <span>Modules</span>
              <strong>Core and reserved areas</strong>
            </div>
          </div>

          <div className="module-grid">
            {moduleCards.map((module) => (
              <article
                className={`module-card ${
                  module.sensitivity === "sensitive" ? "is-sensitive" : ""
                } ${module.status === "Active" ? "is-active" : ""}`}
                key={module.name}
              >
                <div className="module-card-header">
                  <span className="module-icon">{module.shortName}</span>
                  <span className="module-class">
                    {module.sensitivity === "sensitive" ? "Sensitive" : "Internal"}
                  </span>
                </div>
                <h2>{module.name}</h2>
                <p>{module.description}</p>
                <div className="module-tags">
                  <span className={module.status === "Active" ? "is-active" : "is-reserved"}>
                    {module.status}
                  </span>
                  <span>{module.status === "Active" ? "Active" : "Planned"}</span>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="reserved-strip" aria-label="Reserved modules">
          <div>
            <p className="eyebrow">Reserved modules</p>
            <h2>Future module work is not active yet</h2>
          </div>
          <div className="reserved-list">
            {reservedModules.map((module) => (
              <span key={module.name}>{module.name}</span>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}
