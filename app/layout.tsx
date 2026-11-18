import type React from "react"
import type { Metadata } from "next"
import { Geist, Geist_Mono } from "next/font/google"
import { Analytics } from "@vercel/analytics/next"
import "./globals.css"

const geist = Geist({ subsets: ["latin"] })
const geistMono = Geist_Mono({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "Ashmin Aryal | Cybersecurity Analyst",
  description: "Ashmin Aryal is a final-year Cyber Security student in Sydney with hands-on experience in cloud security, identity protection, and security monitoring.",
  metadataBase: new URL("https://ashminaryal.info"),
  openGraph: {
    title: "Ashmin Aryal | Cybersecurity Analyst",
    description: "Cloud security, identity protection, and hands-on defensive security projects.",
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

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className={geist.className}>
      {/* <CHANGE> Applied Geist font to html element */}
      <body className={`${geistMono.className} antialiased`}>
        {children}
        <Analytics />
      </body>
    </html>
  )
}
