const publicProjects = [
  {
    name: "BielOS Core",
    description: "Operating-system-style interface for public project entry points.",
    status: "Online"
  },
  {
    name: "Public Labs",
    description: "Selected experiments and technical notes prepared for public viewing.",
    status: "Curated"
  },
  {
    name: "Project Index",
    description: "A clean route into public work without exposing private hub details.",
    status: "Limited"
  }
];

const hubUrl = process.env.NEXT_PUBLIC_HUB_URL ?? "https://hub.biel.dev.br";

export default function PublicLandingPage() {
  return (
    <main className="os-screen">
      <section className="desktop-shell" aria-label="BielOS public landing">
        <header className="top-bar">
          <div className="brand-lockup">
            <img src="/bielos-mark.svg" alt="" className="brand-mark" />
            <span>BielOS</span>
          </div>
          <div className="status-pill" aria-label="Public status">
            <span className="pulse" />
            Public node stable
          </div>
        </header>

        <section className="hero-panel">
          <div className="terminal-strip">
            <span />
            <span />
            <span />
          </div>
          <p className="eyebrow">biel.dev.br</p>
          <h1>BielOS</h1>
          <p className="description">
            A personal operating-system-style hub for projects, tools, archives,
            automation, and technical labs.
          </p>
          <a className="enter-button" href={hubUrl}>
            Enter hub
          </a>
        </section>

        <section className="project-grid" aria-label="Public projects">
          {publicProjects.map((project) => (
            <article className="project-card" key={project.name}>
              <div>
                <p className="card-kicker">{project.status}</p>
                <h2>{project.name}</h2>
              </div>
              <p>{project.description}</p>
            </article>
          ))}
        </section>

        <footer className="status-line">
          <span>Generic status: available</span>
          <span>Public surface only</span>
        </footer>
      </section>
    </main>
  );
}
