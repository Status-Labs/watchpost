import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono, JetBrains_Mono } from "next/font/google";
import Link from "next/link";
import { ImportNotice } from "@/components/import-notice";
import { Logo } from "@/components/logo";
import { KEV_CATALOG_URL, SITE_DESCRIPTION, SITE_NAME, SOURCE_URL, siteUrl } from "@/lib/site";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });
// Only for the wordmark, matching the logo design.
const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
  weight: "700",
});

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl()),
  title: { default: `${SITE_NAME}: CVE alerts for your stack`, template: `%s · ${SITE_NAME}` },
  description: SITE_DESCRIPTION,
  alternates: {
    types: { "application/rss+xml": [{ url: "/feed.xml", title: `${SITE_NAME} new vulnerabilities` }] },
  },
};

export const viewport: Viewport = { themeColor: "#0a0a0a", colorScheme: "dark" };

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} ${jetbrainsMono.variable} h-full antialiased`}
    >
      <body className="flex min-h-full flex-col font-sans">
        <SiteHeader />
        <ImportNotice />
        <main className="flex-1">{children}</main>
        <SiteFooter />
      </body>
    </html>
  );
}

function SiteHeader() {
  return (
    <header className="sticky top-0 z-10 border-b border-border bg-background/80 backdrop-blur">
      <div className="mx-auto flex h-14 w-full max-w-5xl items-center justify-between gap-4 px-4">
        <Link href="/" aria-label={`${SITE_NAME} home`} className="min-h-11 content-center">
          <Logo compact />
        </Link>
        <nav className="flex items-center gap-1 sm:gap-4">
          <Link href="/vulns" className="label min-h-11 content-center px-2 text-muted hover:text-foreground">
            CVEs
          </Link>
          <Link href="/check" className="label min-h-11 content-center px-2 text-muted hover:text-foreground">
            Check
          </Link>
          <Link href="/rss" className="label min-h-11 content-center px-2 text-muted hover:text-foreground">
            RSS
          </Link>
          <Link href="/docs" className="label min-h-11 content-center px-2 text-muted hover:text-foreground">
            Docs
          </Link>
        </nav>
      </div>
    </header>
  );
}

function SiteFooter() {
  return (
    <footer className="border-t border-border">
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-4 px-4 py-8 text-sm text-muted sm:flex-row sm:items-center sm:justify-between">
        <p>
          Vulnerability data from{" "}
          <a href="https://osv.dev" className="underline hover:text-foreground">
            OSV.dev
          </a>
          , licensed under{" "}
          <a href="https://creativecommons.org/licenses/by/4.0/" className="underline hover:text-foreground">
            CC BY 4.0
          </a>
          , and the{" "}
          <a href={KEV_CATALOG_URL} className="underline hover:text-foreground">
            CISA KEV catalog
          </a>
          .
        </p>
        <nav className="flex flex-wrap gap-x-4 gap-y-2">
          <Link href="/docs" className="label min-h-11 content-center hover:text-foreground sm:min-h-0">
            Docs
          </Link>
          <a href={SOURCE_URL} className="label min-h-11 content-center hover:text-foreground sm:min-h-0">
            GitHub
          </a>
          <a href="/llms.txt" className="label min-h-11 content-center hover:text-foreground sm:min-h-0">
            llms.txt
          </a>
          <a href="/.well-known/security.txt" className="label min-h-11 content-center hover:text-foreground sm:min-h-0">
            Security
          </a>
        </nav>
      </div>
    </footer>
  );
}
