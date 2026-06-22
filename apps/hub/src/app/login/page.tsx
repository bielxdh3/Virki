import { redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";

export const dynamic = "force-dynamic";

type LoginPageProps = {
  searchParams?: Promise<{
    error?: string;
  }>;
};

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const session = await getCurrentSession();
  const params = await searchParams;

  if (session) {
    redirect("/");
  }

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

        <form className="login-form" action="/api/login" method="post">
          <label>
            Access identity
            <input type="email" name="email" autoComplete="email" required />
          </label>
          <label>
            Passphrase
            <input type="password" name="password" autoComplete="current-password" required />
          </label>
          {params?.error ? (
            <p className="login-error" role="alert">
              Invalid email or password.
            </p>
          ) : null}
          <button type="submit">Unlock hub</button>
        </form>

        <p className="login-note">
          Internal access is required before the private hub can open.
        </p>
      </section>
    </main>
  );
}
