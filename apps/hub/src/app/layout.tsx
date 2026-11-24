import type { Metadata } from "next";
import "./globals.css";

// The 404 document must render per request so Next can nonce its bootstrap
// scripts with the CSP issued by the Hub/Portal proxy.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Virki",
  description: "Identidade, autenticação e acesso para projetos privados."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="pt-BR"><body>{children}</body></html>;
}
