export default function SandboxLandingPage() {
  const sandboxes = [
    { href: "/sandbox/sql", label: "/sandbox/sql", desc: "SQL injection lab focused on classic payloads, detection signals, and safe parameterised query patterns." },
    { href: "/sandbox/xss", label: "/sandbox/xss", desc: "Reflected XSS and malicious payload exercises with output encoding and server-side filtering." },
    { href: "/sandbox/rate-limit", label: "/sandbox/rate-limit", desc: "Automated/bot-style traffic, scanners, and WAF-style token-bucket rate limiting with event logging." },
    { href: "/chat", label: "/chat", desc: "Prompt injection lab targeting the Digital Twin chatbot, with every attempt analysed, blocked where necessary, and written to the audit trail." },
    { href: "/sandbox/auth", label: "/sandbox/auth", desc: "Authentication and authorisation lab covering broken access control, privilege escalation attempts, and misconfigured secrets." },
  ];

  return (
    <div className="cyber-bg">
      <main className="container-md" style={{ paddingTop: 40, paddingBottom: 40 }}>
        <a href="/" style={{ fontSize: 13, display: "inline-block", marginBottom: 16 }}>
          {"<- Back to site"}
        </a>
        <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 16 }}>Offensive security sandbox</h1>
        <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 24 }}>
          This environment behaves like a compact, production-grade attack surface. Each endpoint
          is instrumented end-to-end so you can safely point scanners, HTTP clients, or custom
          scripts at it while the backend classifies traffic, rate-limits abuse, and feeds
          telemetry into the security dashboard.
        </p>

        <ul style={{ listStyle: "none", padding: 0, display: "flex", flexDirection: "column", gap: 12 }}>
          {sandboxes.map((s) => (
            <li key={s.href} className="link-card">
              <a href={s.href} style={{ fontWeight: 500, fontSize: 14 }}>{s.label}</a>
              <span style={{ color: "var(--fg-muted)", fontSize: 13 }}>{" — " + s.desc}</span>
            </li>
          ))}
        </ul>

        <p style={{ color: "var(--fg-muted)", fontSize: 12, lineHeight: 1.7, marginTop: 24 }}>
          Treat this like a small, dedicated target in a professional red-team lab: attack only the
          endpoints documented here, observe how they are classified on the dashboard, and do not
          reuse payloads against systems you do not own.
        </p>
      </main>
    </div>
  );
}
