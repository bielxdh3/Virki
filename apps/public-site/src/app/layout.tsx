import type { Metadata } from "next";
import { getLocale } from "./locale";
import "./globals.css";

export const metadata: Metadata = {
  title: "BielOS",
  description: "A personal operating-system-style project hub."
};

export default async function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  const locale = await getLocale();

  return (
    <html lang={locale}>
      <body>{children}</body>
    </html>
  );
}
