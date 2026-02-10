export const metadata = {
  title: "Digital Twin III",
  description: "Cyber-Hardened Portfolio with sandbox and security dashboard"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0 }}>{children}</body>
    </html>
  );
}
