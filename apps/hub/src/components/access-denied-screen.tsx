export function AccessDeniedScreen() {
  return (
    <main className="login-screen">
      <section className="login-window" aria-label="Access boundary unavailable">
        <div className="login-brand">
          <img src="/hub-mark.svg" alt="" />
          <div>
            <p className="eyebrow">hub.biel.dev.br</p>
            <h1>Access unavailable</h1>
          </div>
        </div>
        <p className="login-note">
          The external access boundary must validate before the private hub can open.
        </p>
      </section>
    </main>
  );
}
