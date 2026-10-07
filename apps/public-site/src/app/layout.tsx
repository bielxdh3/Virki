import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Virki",
  description: "Identidade e acesso para projetos privados."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="pt-BR"><body>{children}</body></html>;
}
