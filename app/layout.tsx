import type React from "react"
import type { Metadata, Viewport } from "next"
import { Geist, Geist_Mono } from "next/font/google"
import { Analytics } from "@vercel/analytics/next"
import { RangeRunProvider } from "./range-run-context"
import "./globals.css"

const geist = Geist({ subsets: ["latin"], variable: "--font-geist-sans" })
const geistMono = Geist_Mono({ subsets: ["latin"], variable: "--font-geist-mono" })

export const metadata: Metadata = {
  title: "Digital Twin III | Live Hacking Lab",
  description: "Practice web security in a controlled cyber range. Explore simulated attack scenarios, observe defensive signals, and learn how security controls respond.",
  keywords: ["live hacking lab", "cyber range", "web security training", "security simulations", "defensive engineering"],
  metadataBase: new URL("https://digital-twin-digitalmind222.vercel.app"),
  openGraph: {
    title: "Digital Twin III | Live Hacking Lab",
    description: "A controlled cyber range for practicing web security and exploring defensive controls.",
    url: "https://digital-twin-digitalmind222.vercel.app",
    siteName: "Digital Twin III | Live Hacking Lab",
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
