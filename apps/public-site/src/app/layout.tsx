import type { Metadata } from "next";
import { publicSiteMetadata } from "./discovery";
import { getLocale } from "./locale";
import "./globals.css";

export const metadata: Metadata = publicSiteMetadata;

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
