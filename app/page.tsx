"use client";

export default function Home() {
  return (
    <>
      <div
        className="cyber-bg"
        style={{
          minHeight: "100vh",
          color: "#f9fafb",
          fontFamily:
            "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
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
            <a href="/#about" style={{ color: "#e5e7eb", textDecoration: "none" }}>
              About
            </a>
            <a href="/#sandbox" style={{ color: "#e5e7eb", textDecoration: "none" }}>
              Sandbox
            </a>
            <a href="/#threats" style={{ color: "#e5e7eb", textDecoration: "none" }}>
              Threats
            </a>
            <a href="/#stack" style={{ color: "#e5e7eb", textDecoration: "none" }}>
              Stack
            </a>
            <a href="/lab" style={{ color: "#e5e7eb", textDecoration: "none" }}>
              Lab Case Study
            </a>
            <a href="/dashboard" style={{ color: "#e5e7eb", textDecoration: "none" }}>
              Dashboard
            </a>
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
            alignItems: "stretch",
            marginBottom: 40,
          }}
        >
          {/* Left: personal summary & CTAs */}
          <div style={{ flex: 1, minWidth: 260 }}>
            <p
              style={{
                fontSize: 12,
                letterSpacing: 2,
                color: "#a5b4fc",
                textTransform: "uppercase",
              }}
            >
              Cyber-Hardened Portfolio
            </p>
            <h1 style={{ fontSize: 32, margin: "8px 0 4px" }}>Ashmin Aryal</h1>
            <p style={{ fontSize: 18, color: "#38bdf8", marginBottom: 12 }}>
              Cybersecurity-focused Software Engineer
            </p>
            <p
              style={{
                color: "#9ca3af",
                fontSize: 14,
                maxWidth: 560,
                marginBottom: 8,
              }}
            >
              A secure, cloud-deployed AI portfolio developed through teamwork and real-world
              testing. This Digital Twin is more than a websiteit is a live cyber lab designed
              to detect threats, protect data, and demonstrate observable security practices.
            </p>
            <p
              style={{
                color: "#9ca3af",
                fontSize: 14,
                maxWidth: 560,
                marginBottom: 8,
              }}
            >
              Built within an industry-aligned program, it showcases cloud deployment,
              cybersecurity engineering, and collaborative software development using
              modern AI tools.
            </p>
            <p style={{ color: "#e5e7eb", fontSize: 13, fontWeight: 500 }}>
              Secure. Monitored. Production-ready. Built to be tested, attacked, and improved.
            </p>
            <div
              style={{
                marginTop: 16,
                display: "flex",
                gap: 12,
                flexWrap: "wrap",
              }}
            >
              <a
                href="/#sandbox"
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
              <a
                href="/dashboard"
                style={{
                  padding: "8px 14px",
                  borderRadius: 999,
                  border: "1px solid #4b5563",
                  background: "transparent",
                  color: "#e5e7eb",
                  fontSize: 14,
                  textDecoration: "none",
                }}
              >
                View security dashboard
              </a>
              <a
                href="/lab"
                style={{
                  padding: "8px 14px",
                  borderRadius: 999,
                  border: "1px solid #4b5563",
                  background: "transparent",
                  color: "#e5e7eb",
                  fontSize: 14,
                  textDecoration: "none",
                }}
              >
                Read case study
              </a>
            </div>
          </div>

          {/* Right: security overview card (no chatbot) */}
          <div
            style={{
              flexBasis: 280,
              flexGrow: 0,
              flexShrink: 0,
              borderRadius: 20,
              padding: 16,
              background:
                "radial-gradient(circle at top, rgba(56,189,248,0.35), transparent 60%), #020617",
              border: "1px solid rgba(148,163,184,0.4)",
              display: "flex",
              flexDirection: "column",
              gap: 12,
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div>
                <p style={{ fontSize: 11, color: "#c4b5fd", margin: 0 }}>Live Lab</p>
                <p style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>Attack surface summary</p>
              </div>
              <span
                style={{
                  fontSize: 10,
                  padding: "4px 8px",
                  borderRadius: 999,
                  background: "rgba(34,197,94,0.15)",
                  color: "#4ade80",
                }}
              >
                Online
              </span>
            </div>
            <div
              style={{
                borderRadius: 14,
                background: "rgba(15,23,42,0.9)",
                padding: 10,
                fontSize: 12,
                color: "#e5e7eb",
              }}
            >
              <ul style={{ margin: 0, paddingLeft: 16 }}>
                <li>Target SQL injection, XSS, and auth flaws in safe sandboxes.</li>
                <li>Every attempt is logged to the security dashboard.</li>
                <li>Use your own tools and payloadsthis lab is built to be attacked.</li>
              </ul>
            </div>
            <a
              href="/dashboard"
              style={{
                marginTop: "auto",
                fontSize: 12,
                padding: "8px 10px",
                borderRadius: 999,
                border: "1px solid #4b5563",
                textDecoration: "none",
                color: "#e5e7eb",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span>Open security dashboard</span>
              <span>↗</span>
            </a>
          </div>
        </section>

        {/* About */}
        <section id="about" style={{ marginBottom: 32, scrollMarginTop: 96 }}>
          <h2 style={{ fontSize: 20, marginBottom: 8 }}>What this Digital Twin represents</h2>
          <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 8 }}>
            Every production web app is a target. This Digital Twin turns that risk into a
            teaching tool: a controlled cyber range where you can deliberately attack, observe
            detections and blocks, practise incident response, and document how you harden the
            system release by release.
          </p>
          <p style={{ color: "#9ca3af", fontSize: 14 }}>
            For hiring managers, this site is both a portfolio and a live security case study:
            it hosts my professional identity and projects, exposes safe attack surfaces, and
            shows how I manage security as an ongoing lifecycle instead of a one-time checkbox.
          </p>
        </section>

        {/* Threats & Defenses */}
        <section id="threats" style={{ marginBottom: 32, scrollMarginTop: 96 }}>
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
        <section id="sandbox" style={{ marginBottom: 32, scrollMarginTop: 96 }}>
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
              ��� SQL injection payloads, detection, and safe query patterns.
            </li>
            <li>
              <a href="/sandbox/xss" style={{ color: "#38bdf8" }}>
                /sandbox/xss
              </a>{" "}
              ��� reflected XSS attempts, output encoding, and malicious payload detection.
            </li>
            <li>
              <a href="/sandbox/rate-limit" style={{ color: "#38bdf8" }}>
                /sandbox/rate-limit
              </a>{" "}
              ��� automated/bot-style traffic, scanners, and basic WAF-style rate limiting.
            </li>
            <li>
              <a href="/sandbox/auth" style={{ color: "#38bdf8" }}>
                /sandbox/auth
              </a>{" "}
              ��� authentication failures, broken access control, and privilege-abuse scenarios.
            </li>
          </ul>
        </section>

        {/* Stack */}
        <section id="stack" style={{ marginBottom: 32, scrollMarginTop: 96 }}>
          <h2 style={{ fontSize: 20, marginBottom: 8 }}>Security-focused stack behind the lab</h2>
          <ul style={{ fontSize: 14, color: "#e5e7eb" }}>
            <li>Next.js (App Router) + TypeScript for a modern, testable, security-first frontend.</li>
            <li>Supabase for database, authentication, and structured security event logging.</li>
            <li>Arcjet for WAF protections, basic bot controls, and rate limiting.</li>
            <li>Security utility functions for injection detection, sanitisation, and logging.</li>
            <li>Vercel for hardened deployments, previews, and production-like environments.</li>
          </ul>
        </section>

        {/* Team mission */}
        <section style={{ marginBottom: 32 }}>
          <h2 style={{ fontSize: 20, marginBottom: 8 }}>Team mission & collaboration</h2>
          <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 8 }}>
            Our mission is to design and deploy intelligent digital systems that are secure,
            resilient, and production-ready. We believe modern web applications must be built
            with security as a continuous lifecycle, supported by collaborative development,
            real-world testing, and measurable improvement.
          </p>
          <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 8 }}>
            Through structured teamwork and cloud-based deployment, we transform concepts into
            defensible, operational systems that reflect professional engineering standards.
            This lab was built using Next.js/React, the OpenAI API, Supabase, and Vercel, with
            GitHub and ClickUp underpinning version control and project coordination.
          </p>
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
      <style jsx global>{`
        .cyber-bg {
          position: relative;
          background:
            radial-gradient(circle at top, rgba(56,189,248,0.18), transparent 55%),
            #050816;
          overflow: hidden;
        }

        .cyber-bg::before {
          content: "";
          position: fixed;
          inset: -200px;
          background:
            radial-gradient(circle at 10% 20%, rgba(34,197,94,0.18), transparent 55%),
            radial-gradient(circle at 80% 80%, rgba(56,189,248,0.18), transparent 55%),
            repeating-linear-gradient(
              120deg,
              rgba(15,23,42,0.6) 0px,
              rgba(15,23,42,0.6) 1px,
              transparent 1px,
              transparent 3px
            );
          opacity: 0.9;
          mix-blend-mode: screen;
          animation: cyberShift 18s linear infinite;
          pointer-events: none;
          z-index: -1;
        }

        @keyframes cyberShift {
          from {
            transform: translate3d(0, 0, 0);
          }
          to {
            transform: translate3d(-220px, -220px, 0);
          }
        }
      `}</style>
    </>
  );
}
