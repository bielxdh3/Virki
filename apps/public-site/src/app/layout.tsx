import type { Metadata } from "next";
import { publicCanonicalLink, publicSiteMetadata } from "./discovery";
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
      <head>
        <link rel={publicCanonicalLink.rel} href={publicCanonicalLink.href} />
      </head>
      <body>{children}</body>
    </html>
  );
}
