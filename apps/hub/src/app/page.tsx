import { moduleCatalog } from "@bielos/ui";
import { redirect } from "next/navigation";
import { getCurrentSession } from "../lib/auth";

export const dynamic = "force-dynamic";

const moduleCards = [
  {
    name: "BielOS Core",
    shortName: "OS",
    description: "Core hub shell, session boundary, and command center surface.",
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
  { label: "Public surface", value: "Online" },
  { label: "Private hub", value: "Guarded" },
  { label: "Tunnel path", value: "Managed" },
  { label: "Module data", value: "Not mounted" }
];

const securityLayers = [
  {
    name: "Cloudflare Access",
    description: "Edge gate before private hub traffic reaches BielOS.",
    state: "Layer 01"
  },
  {
    name: "BielOS Internal Auth",
    description: "Application session required before the dashboard opens.",
    state: "Layer 02"
  }
];

export default async function HubDashboardPage() {
  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  const reservedModules = moduleCards.filter((module) => module.status !== "Active");

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
            <span aria-hidden="true">OV</span>
            <strong>Overview</strong>
          </a>
          <a href="#modules" aria-label="View modules">
            <span aria-hidden="true">MD</span>
            <strong>Modules</strong>
          </a>
          <a href="#security" aria-label="View security layers">
            <span aria-hidden="true">SC</span>
            <strong>Security</strong>
          </a>
          <a href="#operations" aria-label="View operations">
            <span aria-hidden="true">OP</span>
            <strong>Ops</strong>
          </a>
        </nav>

        <div className="dock-footer">
          <span>Runtime</span>
          <strong>Core shell active</strong>
        </div>
      </aside>

      <section className="hub-workspace">
        <header className="top-statusbar">
          <div className="statusbar-left">
            <span className="status-dot" aria-hidden="true" />
            <span>hub.biel.dev.br</span>
            <span>Protected session</span>
          </div>
          <form action="/api/logout" method="post">
            <button className="icon-command" type="submit" aria-label="Log out">
              <span aria-hidden="true">IO</span>
              <span>Log out</span>
            </button>
          </form>
        </header>

        <section className="identity-panel" id="overview" aria-label="System identity">
          <div>
            <p className="eyebrow">BielOS command center</p>
            <h1>Private desktop shell</h1>
            <p>
              A guarded workspace for projects, automation, archives, and technical labs.
              Future modules stay reserved until the core remains stable.
            </p>
          </div>
          <div className="identity-meter" aria-label="Core readiness">
            <span>Core</span>
            <strong>Ready</strong>
          </div>
        </section>

        <section className="dashboard-grid" aria-label="Hub dashboard">
          <article className="panel session-panel">
            <div className="panel-title">
              <span>Session</span>
              <strong>Unlocked</strong>
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

          <article className="panel deployment-panel" id="operations">
            <div className="panel-title">
              <span>Deployment</span>
              <strong>Remote path active</strong>
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

          <article className="panel security-panel" id="security">
            <div className="panel-title">
              <span>Security Layers</span>
              <strong>Two gates</strong>
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
              <strong>Non-destructive</strong>
            </div>
            <div className="action-stack">
              <a href="#modules">View modules</a>
              <a href="#operations">View deployment status</a>
              <form action="/api/logout" method="post">
                <button type="submit">Log out</button>
              </form>
            </div>
          </article>
        </section>

        <section className="module-window" id="modules" aria-label="Module grid">
          <div className="window-titlebar">
            <div>
              <span>Module bay</span>
              <strong>Core and reserved surfaces</strong>
            </div>
            <div className="window-controls" aria-hidden="true">
              <i />
              <i />
              <i />
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
                  <span>{module.status}</span>
                  <span>{module.status === "Active" ? "Active" : "Planned"}</span>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="reserved-strip" aria-label="Reserved modules">
          <div>
            <p className="eyebrow">Reserved modules</p>
            <h2>Future module work remains parked</h2>
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
