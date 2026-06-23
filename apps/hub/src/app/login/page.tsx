import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getCurrentSession } from "../../lib/auth";
import { isCloudflareAccessAllowed, validateHubCloudflareAccess } from "../../lib/cloudflare-access";

export const dynamic = "force-dynamic";

type LoginPageProps = {
  searchParams?: Promise<{
    error?: string;
  }>;
};

export default async function LoginPage({ searchParams }: LoginPageProps) {
  const requestHeaders = await headers();
  const accessResult = await validateHubCloudflareAccess(requestHeaders, "hub-login-page");

  if (!isCloudflareAccessAllowed(accessResult)) {
    return <AccessDeniedScreen />;
  }

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

function AccessDeniedScreen() {
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
          The external access boundary must validate before the internal login can open.
        </p>
      </section>
    </main>
  );
}
