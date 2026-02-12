"use client";

export default function Home() {
  const rollDice = () => {
    const result = Math.floor(Math.random() * 6) + 1;
    alert("You rolled: " + result);
  };
  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#050816",
        color: "#f9fafb",
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
      }}
    >
      <header
        style={{
          borderBottom: "1px solid rgba(148,163,184,0.3)",
          backdropFilter: "blur(8px)",
          position: "sticky",
          top: 0,
          zIndex: 10,
        }}
      >
        <div
          style={{
            maxWidth: 1040,
            margin: "0 auto",
            padding: "16px 24px",
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span
              style={{
                width: 10,
                height: 10,
                borderRadius: "999px",
                background: "#22c55e",
                boxShadow: "0 0 12px #22c55e",
              }}
            />
            <span style={{ fontWeight: 600 }}>Digital Twin III</span>
          </div>
          <nav style={{ display: "flex", gap: 16, fontSize: 14 }}>
            <a href="#about" style={{ color: "#e5e7eb", textDecoration: "none" }}>About</a>
            <a href="#sandbox" style={{ color: "#e5e7eb", textDecoration: "none" }}>Sandbox</a>
            <a href="#threats" style={{ color: "#e5e7eb", textDecoration: "none" }}>Threats</a>
            <a href="#stack" style={{ color: "#e5e7eb", textDecoration: "none" }}>Stack</a>
            <a href="/lab" style={{ color: "#e5e7eb", textDecoration: "none" }}>Lab Case Study</a>
            <a href="/dashboard" style={{ color: "#e5e7eb", textDecoration: "none" }}>Dashboard</a>
          </nav>
        </div>
      </header>

      <main style={{ maxWidth: 1040, margin: "0 auto", padding: "32px 24px 40px" }}>
        {/* Hero */}
        <section
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 32,
            alignItems: "center",
            marginBottom: 40,
          }}
        >
          <div style={{ flex: 1, minWidth: 260 }}>
            <p style={{ fontSize: 12, letterSpacing: 2, color: "#a5b4fc", textTransform: "uppercase" }}>
              Live Cyber Lab · Hack Me If You Can
            </p>
            <h1 style={{ fontSize: 32, margin: "8px 0 12px" }}>
              A real hacking lab that invites attack and shows how you defend.
            </h1>
            <p style={{ color: "#9ca3af", fontSize: 14, maxWidth: 560 }}>
              This is not a static portfolio. It is a live security lab where you can launch
              common web attacks, watch them being detected and blocked in real time, and see
              how telemetry, dashboards, and remediation flow together.
            </p>
            <div style={{ marginTop: 16, display: "flex", gap: 12, flexWrap: "wrap" }}>
              <a
                href="#sandbox"
                style={{
                  padding: "8px 14px",
                  borderRadius: 999,
                  background: "#22c55e",
                  color: "#020617",
                  fontSize: 14,
                  textDecoration: "none",
                  fontWeight: 500,
                }}
              >
                Explore attack sandbox
              </a>
              <button
                onClick={rollDice}
                style={{
                  padding: "8px 14px",
                  borderRadius: 999,
                  border: "1px solid #4b5563",
                  background: "transparent",
                  color: "#e5e7eb",
                  fontSize: 14,
                  cursor: "pointer",
                }}
              >
                Roll security dice 🎲
              </button>
            </div>
          </div>
          <div
            style={{
              flexBasis: 260,
              flexGrow: 0,
              flexShrink: 0,
              borderRadius: 16,
              padding: 16,
              background:
                "radial-gradient(circle at top, rgba(56,189,248,0.25), transparent 55%), #020617",
              border: "1px solid rgba(148,163,184,0.4)",
            }}
          >
            <p style={{ fontSize: 12, color: "#9ca3af", marginBottom: 8 }}>What this lab proves</p>
            <ul style={{ listStyle: "none", padding: 0, margin: 0, fontSize: 13 }}>
              <li> Hosts your professional identity &amp; real security projects</li>
              <li> Lets visitors actively attack safe sandboxes (SQLi, XSS, auth bypass, bots)</li>
              <li> Detects &amp; blocks threats in real time with logging and dashboards</li>
              <li> Analyses attacker behaviour, CVSS-style risk, and remediation history</li>
              <li> Demonstrates how you design, test, and harden defences as a lifecycle</li>
            </ul>
          </div>
        </section>

        {/* About */}
        <section id="about" style={{ marginBottom: 32 }}>
          <h2 style={{ fontSize: 20, marginBottom: 8 }}>What this Digital Twin represents</h2>
          <p style={{ color: "#9ca3af", fontSize: 14 }}>
            Every production web app is a target. This Digital Twin turns that risk into a
            teaching tool: a controlled cyber range where you can deliberately attack, observe
            detections and blocks, practise incident response, and document how you harden the
            system release by release.
          </p>
        </section>

        {/* Threats & Defenses */}
        <section id="threats" style={{ marginBottom: 32 }}>
          <h2 style={{ fontSize: 20, marginBottom: 8 }}>Threats you train against</h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
              gap: 16,
              fontSize: 14,
            }}
          >
            <div style={{ padding: 12, borderRadius: 12, border: "1px solid #1f2937" }}>
              <h3 style={{ fontSize: 15, marginBottom: 6 }}>Injection attacks</h3>
              <p style={{ color: "#9ca3af" }}>SQL injection, prompt injection, and malicious payloads.</p>
            </div>
            <div style={{ padding: 12, borderRadius: 12, border: "1px solid #1f2937" }}>
              <h3 style={{ fontSize: 15, marginBottom: 6 }}>Auth &amp; access control</h3>
              <p style={{ color: "#9ca3af" }}>Authentication failures, broken access control, privilege abuse.</p>
            </div>
            <div style={{ padding: 12, borderRadius: 12, border: "1px solid #1f2937" }}>
              <h3 style={{ fontSize: 15, marginBottom: 6 }}>Bots &amp; automation</h3>
              <p style={{ color: "#9ca3af" }}>Automated scanners, brute-force tools, and scripted attacks.</p>
            </div>
          </div>
        </section>

        {/* Sandbox */}
        <section id="sandbox" style={{ marginBottom: 32 }}>
          <h2 style={{ fontSize: 20, marginBottom: 8 }}>Hacking simulation sandbox</h2>
          <p style={{ color: "#9ca3af", fontSize: 14 }}>
            These live sandboxes are wired to real detection, logging, and rate limiting. You can
            safely try common attacks and immediately see how the application reacts.
          </p>
          <ul style={{ fontSize: 14 }}>
            <li>
              <a href="/sandbox/sql" style={{ color: "#38bdf8" }}>
                /sandbox/sql
              </a>{" "}
               SQL injection payloads, detection, and safe query patterns.
            </li>
            <li>
              <a href="/sandbox/xss" style={{ color: "#38bdf8" }}>
                /sandbox/xss
              </a>{" "}
               reflected XSS attempts, output encoding, and malicious payload detection.
            </li>
            <li>
              <a href="/sandbox/rate-limit" style={{ color: "#38bdf8" }}>
                /sandbox/rate-limit
              </a>{" "}
               automated/bot-style traffic, scanners, and basic WAF-style rate limiting.
            </li>
            <li>
              <a href="/sandbox/auth" style={{ color: "#38bdf8" }}>
                /sandbox/auth
              </a>{" "}
               authentication failures, broken access control, and privilege-abuse scenarios.
            </li>
          </ul>
        </section>

        {/* Stack */}
        <section id="stack" style={{ marginBottom: 32 }}>
          <h2 style={{ fontSize: 20, marginBottom: 8 }}>Security-focused stack behind the lab</h2>
          <ul style={{ fontSize: 14, color: "#e5e7eb" }}>
            <li>Next.js (App Router) + TypeScript for a modern, testable, security-first frontend.</li>
            <li>Supabase for database, authentication, and structured security event logging.</li>
            <li>ArcJet-style patterns for WAF protections, IP reputation, and rate limiting.</li>
            <li>OpenAI agents for digital-twin persona, secure chatbot, and threat analysis.</li>
            <li>Vercel for hardened deployments, previews, and production-like environments.</li>
          </ul>
        </section>

        {/* Call to action */}
        <section style={{ marginBottom: 16 }}>
          <h2 style={{ fontSize: 20, marginBottom: 8 }}>Use this live lab as your case study</h2>
          <p style={{ color: "#9ca3af", fontSize: 14 }}>
            Share this site with recruiters, hiring managers, and mentors. It is a deployable,
            auditable cyber lab that demonstrates how you design, test, and improve defences
            not just theory on a CV, but a running system that can be safely attacked, defended,
            and analysed.
          </p>
        </section>
      </main>
    </div>
  );
}
