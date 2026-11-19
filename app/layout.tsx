import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { RangeRunProvider } from "./range-run-context";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
});

export const metadata: Metadata = {
  title: "Digital Twin III",
  description: "An independently built cyber range by Ashmin Aryal, with controlled security exercises and live defensive telemetry.",
};

export const viewport: Viewport = {
  themeColor: "#050a18",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body><RangeRunProvider>{children}</RangeRunProvider></body>
    </html>
  );
}
