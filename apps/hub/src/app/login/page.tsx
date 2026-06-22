export default function LoginPage() {
  return (
    <main className="login-screen">
      <section className="login-window" aria-label="BielOS internal login">
        <div className="login-brand">
          <img src="/hub-mark.svg" alt="" />
          <div>
            <p className="eyebrow">hub.biel.dev.br</p>
            <h1>BielOS Hub</h1>
          </div>
        </div>

        <form className="login-form">
          <label>
            Access identity
            <input type="email" name="email" placeholder="user@example.com" autoComplete="email" />
          </label>
          <label>
            Passphrase
            <input
              type="password"
              name="password"
              placeholder="Not wired yet"
              autoComplete="current-password"
            />
          </label>
          <button type="button">Unlock placeholder</button>
        </form>

        <p className="login-note">
          Authentication will be connected through the auth package and the
          Cloudflare Access boundary in a later phase.
        </p>
      </section>
    </main>
  );
}
