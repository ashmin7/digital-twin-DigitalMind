import type React from "react"
import type { Metadata, Viewport } from "next"
import { Geist, Geist_Mono } from "next/font/google"
import { Analytics } from "@vercel/analytics/next"
import { RangeRunProvider } from "./range-run-context"
import "./globals.css"

const geist = Geist({ subsets: ["latin"], variable: "--font-geist-sans" })
const geistMono = Geist_Mono({ subsets: ["latin"], variable: "--font-geist-mono" })

export const metadata: Metadata = {
  title: "Ashmin Aryal | Cybersecurity Student & Builder",
  description: "Ashmin Aryal is a final-year Cyber Security student at Victoria University, Sydney, focused on cloud security, identity, defensive monitoring, and hands-on security projects.",
  keywords: ["Ashmin Aryal", "Cybersecurity student", "Cloud security", "Security analyst internship", "Live hacking lab", "Cybersecurity projects"],
  metadataBase: new URL("https://ashminaryal.info"),
  openGraph: {
    title: "Ashmin Aryal | Cybersecurity Student & Builder",
    description: "Cloud security, identity protection, defensive monitoring, and hands-on security projects from Ashmin Aryal.",
    url: "https://ashminaryal.info",
    siteName: "Ashmin Aryal",
    type: "website",
  },
  generator: "v0.app",
  icons: {
    icon: [
      {
        url: "/icon-light-32x32.png",
        media: "(prefers-color-scheme: light)",
      },
      {
        url: "/icon-dark-32x32.png",
        media: "(prefers-color-scheme: dark)",
      },
      {
        url: "/icon.svg",
        type: "image/svg+xml",
      },
    ],
    apple: "/apple-icon.png",
  },
}

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#080d0b",
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className={`${geist.className} ${geistMono.variable}`}>
      <body className="antialiased">
        <RangeRunProvider>{children}</RangeRunProvider>
        <Analytics />
      </body>
    </html>
  )
}
