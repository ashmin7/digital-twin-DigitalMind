import type React from "react"
import type { Metadata, Viewport } from "next"
import { Geist, Geist_Mono } from "next/font/google"
import { Analytics } from "@vercel/analytics/next"
import { RangeRunProvider } from "./range-run-context"
import "./globals.css"

const geist = Geist({ subsets: ["latin"], variable: "--font-geist-sans" })
const geistMono = Geist_Mono({ subsets: ["latin"], variable: "--font-geist-mono" })

export const metadata: Metadata = {
  title: "Ashmin’s Notes | Learning in public",
  description: "A personal notebook of field guides, technical notes, and ideas Ashmin is learning along the way.",
  keywords: ["notes", "learning", "Git", "GitHub", "web development", "study notes"],
  metadataBase: new URL("https://notes.ashminaryal.info"),
  openGraph: {
    title: "Ashmin’s Notes | Learning in public",
    description: "A personal notebook of field guides, technical notes, and ideas Ashmin is learning along the way.",
    url: "https://notes.ashminaryal.info",
    siteName: "Ashmin’s Notes",
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
  themeColor: "#ffffff",
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
