import { moduleCatalog } from "@bielos/ui";
import { redirect } from "next/navigation";
import { getCurrentSession } from "../lib/auth";

export const dynamic = "force-dynamic";

const privateStatus = [
  { label: "Core shell", value: "Ready" },
  { label: "Access layer", value: "Pending" },
  { label: "Module data", value: "Sealed" },
  { label: "Backups", value: "Planned" }
];

export default async function HubDashboardPage() {
  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  return (
    <main className="hub-desktop">
      <aside className="sidebar" aria-label="BielOS navigation">
        <div className="system-mark">
          <img src="/hub-mark.svg" alt="" />
          <div>
            <strong>BielOS</strong>
            <span>Private Hub</span>
          </div>
        </div>

        <nav className="nav-stack" aria-label="Primary">
          <a href="/">Dashboard</a>
          <a href="#modules">Modules</a>
          <a href="#status">Status</a>
        </nav>

        <div className="session-box">
          <span>Session</span>
          <strong>{session.user.email}</strong>
          <span>{session.user.role}</span>
        </div>
      </aside>

      <section className="workspace">
        <header className="workspace-header">
          <div>
            <p className="eyebrow">hub.biel.dev.br</p>
            <h1>Command dashboard</h1>
          </div>
          <form action="/api/logout" method="post">
            <button className="lock-button" type="submit">
              Log out
            </button>
          </form>
        </header>

        <section className="status-grid" id="status" aria-label="Private status">
          {privateStatus.map((item) => (
            <article className="status-card" key={item.label}>
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </article>
          ))}
        </section>

        <section className="window" id="modules" aria-label="Reserved modules">
          <div className="window-titlebar">
            <span>Reserved module bay</span>
            <div className="window-controls" aria-hidden="true">
              <i />
              <i />
              <i />
            </div>
          </div>

          <div className="module-grid">
            {moduleCatalog.map((module) => (
              <article
                className={`module-card ${
                  module.sensitivity === "sensitive" ? "is-sensitive" : ""
                }`}
                key={module.slug}
              >
                <div className="module-card-header">
                  <span className="module-icon">{module.shortName}</span>
                  <span className="sensitivity">
                    {module.sensitivity === "sensitive" ? "Sensitive" : "Internal"}
                  </span>
                </div>
                <h2>{module.name}</h2>
                <p>{module.description}</p>
                <span className="module-state">{module.status}</span>
              </article>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}
