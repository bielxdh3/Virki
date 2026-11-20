import type { Metadata } from "next";
import "./globals.css";

// Every HTML document, including not-found pages, needs request-time CSP.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Virki",
  description: "Identidade e acesso para projetos privados."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="pt-BR"><body>{children}</body></html>;
}
