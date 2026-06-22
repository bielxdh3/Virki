const publicProjects = [
  {
    name: "BielOS Core",
    description: "Core interface and public entry point for the BielOS project.",
    status: "Public"
  },
  {
    name: "L-vault",
    description: "Reserved module space for future personal tooling.",
    status: "Reserved"
  },
  {
    name: "root.ark",
    description: "Reserved module space for future archive workflows.",
    status: "Reserved"
  },
  {
    name: "H-vault",
    description: "Reserved module space for future organized storage.",
    status: "Reserved"
  },
  {
    name: "GymForge",
    description: "Reserved module space for future training tools.",
    status: "Reserved"
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
            Public status available
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
