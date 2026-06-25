import { prisma } from "@bielos/database";
import { headers } from "next/headers";
import { forbidden, redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";

export const dynamic = "force-dynamic";

const foundationItems = [
  "Participant records",
  "Exercise catalog",
  "Attendance schema",
  "Workout notes",
  "Workout sets",
  "Competition metadata"
];

const formatCount = (count: number) => new Intl.NumberFormat("en-US").format(count);

export default async function GymForgePage() {
  const requestHeaders = await headers();
  const accessResult = await validateHubCloudflareAccess(requestHeaders, "gymforge");

  if (!isCloudflareAccessAllowed(accessResult)) {
    forbidden();
  }

  const session = await getCurrentSession();

  if (!session) {
    redirect("/login");
  }

  const [
    participantsCount,
    activeParticipantsCount,
    exerciseCatalogCount,
    competitionsCount,
    viewerParticipant
  ] = await Promise.all([
    prisma.gymForgeParticipant.count(),
    prisma.gymForgeParticipant.count({ where: { status: "ACTIVE" } }),
    prisma.gymForgeExercise.count({ where: { isActive: true } }),
    prisma.gymForgeCompetition.count(),
    prisma.gymForgeParticipant.findUnique({
      where: { userId: session.user.id },
      select: {
        displayName: true,
        status: true,
        role: true
      }
    })
  ]);

  const metrics = [
    { label: "Participants", value: formatCount(participantsCount) },
    { label: "Active", value: formatCount(activeParticipantsCount) },
    { label: "Exercises", value: formatCount(exerciseCatalogCount) },
    { label: "Competitions", value: formatCount(competitionsCount) }
  ];

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
          <a href="/" aria-label="Return to hub">
            <span aria-hidden="true">01</span>
            <strong>Hub</strong>
          </a>
          <a href="#foundation" aria-label="View GymForge foundation">
            <span aria-hidden="true">02</span>
            <strong>Foundation</strong>
          </a>
          <a href="#status" aria-label="View GymForge status">
            <span aria-hidden="true">03</span>
            <strong>Status</strong>
          </a>
        </nav>

        <div className="dock-footer">
          <span>Module</span>
          <strong>Foundation</strong>
        </div>
      </aside>

      <section className="hub-workspace">
        <header className="top-statusbar">
          <div className="statusbar-left">
            <span className="status-dot" aria-hidden="true" />
            <span>GymForge</span>
            <span>Gated</span>
          </div>
          <a className="icon-command" href="/">
            <span>Back to hub</span>
          </a>
        </header>

        <section className="identity-panel anchor-section" id="status" aria-label="GymForge status">
          <div>
            <p className="eyebrow">GymForge</p>
            <h1>MVP Foundation</h1>
            <p>
              Gated gym competition foundation for invited or admin-created participants.
              Tracking, check-ins, uploads, imports, and public registration are not enabled yet.
            </p>
          </div>
          <div className="identity-meter" aria-label="Implementation status">
            <span>Status</span>
            <strong>Schema only</strong>
          </div>
        </section>

        <section className="dashboard-grid" aria-label="GymForge read status">
          <article className="panel session-panel">
            <div className="panel-title">
              <span>Viewer</span>
              <strong className="status-pill is-active">
                {viewerParticipant ? "Linked" : "Not linked"}
              </strong>
            </div>
            <dl className="detail-list">
              <div>
                <dt>Participant</dt>
                <dd>{viewerParticipant?.displayName ?? "No GymForge participant record"}</dd>
              </div>
              <div>
                <dt>Status</dt>
                <dd>{viewerParticipant?.status ?? "Unavailable"}</dd>
              </div>
              <div>
                <dt>Role</dt>
                <dd>{viewerParticipant?.role ?? "Unavailable"}</dd>
              </div>
            </dl>
          </article>

          <article className="panel deployment-panel">
            <div className="panel-title">
              <span>Registry</span>
              <strong className="status-pill">Read only</strong>
            </div>
            <div className="status-list">
              {metrics.map((metric) => (
                <div key={metric.label}>
                  <span>{metric.label}</span>
                  <strong>{metric.value}</strong>
                </div>
              ))}
            </div>
          </article>
        </section>

        <section className="module-window anchor-section" id="foundation" aria-label="GymForge foundation">
          <div className="window-titlebar">
            <div>
              <span>Foundation</span>
              <strong>Implemented data model boundaries</strong>
            </div>
          </div>

          <div className="module-grid">
            {foundationItems.map((item) => (
              <article className="module-card" key={item}>
                <div className="module-card-header">
                  <span className="module-icon">GF</span>
                  <span className="module-class">Internal</span>
                </div>
                <h2>{item}</h2>
                <p>Foundation model exists. User-facing mutations are not enabled in this phase.</p>
                <div className="module-tags">
                  <span className="is-reserved">No forms</span>
                  <span>Gated</span>
                </div>
              </article>
            ))}
          </div>
        </section>

        <section className="reserved-strip" aria-label="GymForge limitations">
          <div>
            <p className="eyebrow">Safety boundary</p>
            <h2>No private data ingestion is enabled</h2>
            <p>
              GymForge remains behind existing hub auth. Photo proof, check-in creation,
              workout entry, imports, exports, and public registration remain blocked.
            </p>
          </div>
        </section>
      </section>
    </main>
  );
}
