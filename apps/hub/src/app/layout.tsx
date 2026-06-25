import type { Metadata } from "next";
import { getLocale } from "./locale";
import "./globals.css";

export const metadata: Metadata = {
  title: "BielOS Hub",
  description: "Private BielOS hub shell."
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
