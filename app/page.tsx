"use client";
import { useState, useRef, useEffect } from "react";

function SandboxDropdown() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  const items = [
    { href: "/sandbox/sql", label: "SQL Injection" },
    { href: "/sandbox/xss", label: "XSS Testing" },
    { href: "/sandbox/rate-limit", label: "Rate Limiting" },
    { href: "/sandbox/auth", label: "Auth Testing" },
  ];

  return (
    <div ref={ref} style={{ position: "relative" }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          background: "none",
          border: "none",
          color: "var(--fg-muted)",
          cursor: "pointer",
          fontSize: 13,
          fontFamily: "inherit",
          display: "flex",
          alignItems: "center",
          gap: 4,
          padding: 0,
        }}
        onMouseEnter={(e) => (e.currentTarget.style.color = "var(--primary)")}
        onMouseLeave={(e) => {
          if (!open) e.currentTarget.style.color = "var(--fg-muted)";
        }}
      >
        Sandbox
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{
            transition: "transform 0.2s",
            transform: open ? "rotate(180deg)" : "rotate(0deg)",
          }}
        >
          <polyline points="6 9 12 15 18 9" />
        </svg>
      </button>

      {open && (
        <div
          style={{
            position: "absolute",
            top: "calc(100% + 8px)",
            left: "50%",
            transform: "translateX(-50%)",
            background: "var(--bg-card)",
            border: "1px solid var(--border)",
            borderRadius: 10,
            padding: "6px 0",
            minWidth: 180,
            boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
            zIndex: 50,
          }}
        >
          {items.map((item) => (
            <a
              key={item.href}
              href={item.href}
              onClick={() => setOpen(false)}
              style={{
                display: "block",
                padding: "8px 16px",
                fontSize: 13,
                color: "var(--fg)",
                textDecoration: "none",
                transition: "background 0.15s",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "rgba(34,197,94,0.08)";
                e.currentTarget.style.color = "var(--primary)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "transparent";
                e.currentTarget.style.color = "var(--fg)";
              }}
            >
              {item.label}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

export default function Home() {
  return (
    <div className="cyber-bg">
      {/* Header */}
      <header
        style={{
          borderBottom: "1px solid rgba(30,41,59,0.5)",
          backdropFilter: "blur(12px)",
          position: "sticky",
          top: 0,
          zIndex: 10,
        }}
      >
        <div
          className="container"
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            paddingTop: 14,
            paddingBottom: 14,
          }}
        >
          <a href="/" style={{ fontWeight: 600, fontSize: 15, color: "var(--fg)", textDecoration: "none", display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ width: 10, height: 10, borderRadius: "50%", background: "var(--primary)", boxShadow: "0 0 8px var(--primary), 0 0 20px rgba(34,197,94,0.3)", display: "inline-block" }} />
            Digital Twin III
          </a>
          <nav style={{ display: "flex", alignItems: "center", gap: 16, fontSize: 13 }}>
            {[
              { href: "/#about", label: "About" },
              { href: "/#threats", label: "Threats" },
              { href: "/#stack", label: "Stack" },
              { href: "/lab", label: "Lab Case Study" },
            ].map((l) => (
              <a
                key={l.href}
                href={l.href}
                style={{ color: "var(--fg-muted)", textDecoration: "none" }}
                onMouseEnter={(e) => (e.currentTarget.style.color = "var(--primary)")}
                onMouseLeave={(e) => (e.currentTarget.style.color = "var(--fg-muted)")}
              >
                {l.label}
              </a>
            ))}
            <SandboxDropdown />
            <a
              href="/dashboard"
              style={{
                display: "flex",
                alignItems: "center",
                gap: 8,
                padding: "8px 20px",
                fontSize: 13,
                fontWeight: 600,
                color: "var(--primary)",
                border: "2px solid var(--primary)",
                borderRadius: 999,
                background: "transparent",
                textDecoration: "none",
                transition: "background 0.2s, color 0.2s",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "var(--primary)";
                e.currentTarget.style.color = "#000";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "transparent";
                e.currentTarget.style.color = "var(--primary)";
              }}
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                <rect x="1" y="1" width="6" height="6" rx="1" />
                <rect x="9" y="1" width="6" height="6" rx="1" />
                <rect x="1" y="9" width="6" height="6" rx="1" />
                <rect x="9" y="9" width="6" height="6" rx="1" />
              </svg>
              Dashboard
            </a>
          </nav>
        </div>
      </header>

      <main className="container" style={{ paddingTop: 32, paddingBottom: 40 }}>
        {/* Hero */}
        <section style={{ display: "flex", flexWrap: "wrap", gap: 32, alignItems: "stretch", marginBottom: 40 }}>
          <div style={{ flex: "1 1 260px" }}>
            <p style={{ fontSize: 11, letterSpacing: 2, color: "var(--accent)", textTransform: "uppercase" }}>
              Cyber-Hardened Portfolio
            </p>
            <h1 style={{ fontSize: 34, fontWeight: 700, marginTop: 8, marginBottom: 6 }}>DigitalMind</h1>
            <p style={{ color: "var(--fg-muted)", fontSize: 14, maxWidth: 560, marginBottom: 10, lineHeight: 1.7 }}>
              A secure, cloud-deployed AI portfolio developed through teamwork and real-world
              testing. This Digital Twin is more than a website — it is a live hacking lab where
              you can safely attack defined surfaces and watch the detections appear in real time.
            </p>
            <p style={{ color: "var(--fg-muted)", fontSize: 14, maxWidth: 560, marginBottom: 10, lineHeight: 1.7 }}>
              Built within an industry-aligned program, it showcases cloud deployment,
              cybersecurity engineering, and collaborative software development using
              modern AI tools.
            </p>
            <p style={{ fontSize: 13, fontWeight: 500 }}>
              Secure. Monitored. Production-ready. Built to be tested, attacked, and improved.
            </p>
            <div style={{ marginTop: 18, display: "flex", gap: 12, flexWrap: "wrap" }}>
              <a href="/#sandbox" className="btn-primary">Explore attack sandbox</a>
              <a href="/dashboard" className="btn-outline">View security dashboard</a>
              <a href="/lab" className="btn-outline">Read case study</a>
            </div>
          </div>

          {/* Right card - DIGITALMIND TEAM Status */}
          <div
            style={{
              flexBasis: 310,
              flexGrow: 0,
              flexShrink: 0,
              borderRadius: 20,
              padding: 24,
              background: "radial-gradient(ellipse at top, rgba(56,189,248,0.12), transparent 60%), var(--bg-card)",
              border: "1px solid rgba(30,41,59,0.5)",
              display: "flex",
              flexDirection: "column",
              gap: 18,
            }}
          >
            {/* Header */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span style={{ fontSize: 12, fontWeight: 600, letterSpacing: 1.5, textTransform: "uppercase", color: "var(--fg-muted)" }}>
                DIGITALMIND TEAM
              </span>
              <span
                style={{
                  fontSize: 11,
                  fontWeight: 600,
                  color: "var(--primary)",
                  border: "1px solid var(--primary)",
                  borderRadius: 999,
                  padding: "3px 12px",
                }}
              >
                Online
              </span>
            </div>

            {/* Status rows */}
            <div
              style={{
                borderRadius: 14,
                border: "1px solid rgba(30,41,59,0.6)",
                background: "rgba(8,14,30,0.7)",
                padding: "4px 0",
              }}
            >
              {[
                { label: "STATUS", value: "OPERATIONAL", color: "var(--primary)" },
                { label: "ACCESS LEVEL", value: "PUBLIC", color: "var(--fg)" },
                { label: "THREAT DETECTION", value: "ACTIVE", color: "var(--primary)" },
              ].map((row, i, arr) => (
                <div
                  key={row.label}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "12px 18px",
                    borderBottom: i < arr.length - 1 ? "1px solid rgba(30,41,59,0.4)" : "none",
                    fontSize: 13,
                  }}
                >
                  <span style={{ color: "var(--fg-muted)", fontWeight: 500 }}>{row.label}</span>
                  <span style={{ fontWeight: 700, color: row.color }}>{row.value}</span>
                </div>
              ))}
            </div>

            {/* WAF badge */}
            <div style={{ display: "flex", justifyContent: "center" }}>
              <span
                style={{
                  fontSize: 12,
                  fontWeight: 500,
                  color: "var(--fg-muted)",
                  border: "1px solid rgba(30,41,59,0.6)",
                  borderRadius: 999,
                  padding: "6px 18px",
                  background: "rgba(8,14,30,0.5)",
                }}
              >
                WAF Protection ENABLED
              </span>
            </div>
          </div>
        </section>

        {/* About */}
        <section id="about" style={{ marginBottom: 32, scrollMarginTop: 80 }}>
          <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 10 }}>What this Digital Twin represents</h2>
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 8 }}>
            Every production web app is a target. This Digital Twin turns that risk into a
            teaching tool: a controlled cyber range where you can deliberately attack, observe
            detections and blocks, practise incident response, and document how you harden the
            system release by release.
          </p>
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7 }}>
            For hiring managers, this site is both a portfolio and a live security case study:
            it hosts my professional identity and projects, exposes safe attack surfaces, and
            shows how I manage security as an ongoing lifecycle instead of a one-time checkbox.
          </p>
        </section>

        {/* Threats */}
        <section id="threats" style={{ marginBottom: 32, scrollMarginTop: 80 }}>
          <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 10 }}>Threats you train against</h2>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16 }}>
            {[
              { title: "Injection attacks", desc: "SQL injection, prompt injection, and malicious payloads." },
              { title: "Auth & access control", desc: "Authentication failures, broken access control, privilege abuse." },
              { title: "Bots & automation", desc: "Automated scanners, brute-force tools, and scripted attacks." },
            ].map((t) => (
              <div key={t.title} className="link-card">
                <h3 style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>{t.title}</h3>
                <p style={{ color: "var(--fg-muted)", fontSize: 13, margin: 0, lineHeight: 1.6 }}>{t.desc}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Sandbox */}
        <section id="sandbox" style={{ marginBottom: 32, scrollMarginTop: 80 }}>
          <h2 style={{ fontSize: 20, fontWeight: 700, marginBottom: 10 }}>Hacking simulation sandbox</h2>
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 18 }}>
            These live sandboxes are wired to real detection, logging, and rate limiting. You can
            safely try common attacks and immediately see how the application reacts.
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {[
              { href: "/sandbox/sql", path: "/sandbox/sql", desc: "SQL injection payloads, detection, and safe query patterns." },
              { href: "/sandbox/xss", path: "/sandbox/xss", desc: "reflected XSS attempts, output encoding, and malicious payload detection." },
              { href: "/sandbox/rate-limit", path: "/sandbox/rate-limit", desc: "automated/bot-style traffic, scanners, and basic WAF-style rate limiting." },
              { href: "/sandbox/auth", path: "/sandbox/auth", desc: "authentication failures, broken access control, and privilege-abuse scenarios." },
            ].map((s) => (
              <a
                key={s.href}
                href={s.href}
                style={{
                  display: "block",
                  padding: "14px 18px",
                  borderRadius: 10,
                  background: "var(--bg-card)",
                  borderLeft: "3px solid var(--accent)",
                  textDecoration: "none",
                  color: "var(--fg)",
                  fontSize: 14,
                  lineHeight: 1.6,
                }}
              >
                <span style={{ color: "var(--accent)", fontFamily: "monospace", fontWeight: 600 }}>{s.path}</span>
                <span style={{ color: "var(--fg-muted)" }}>{" \u2014 "}{s.desc}</span>
              </a>
            ))}
          </div>
        </section>

        {/* Stack */}
        <section id="stack" style={{ marginBottom: 32, scrollMarginTop: 80 }}>
          <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 10 }}>Security-focused stack behind the lab</h2>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: 12,
            }}
          >
            {[
              {
                name: "Next.js (App Router)",
                desc: "Modern, testable, security-first frontend",
                icon: (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="16 18 22 12 16 6" />
                    <polyline points="8 6 2 12 8 18" />
                  </svg>
                ),
              },
              {
                name: "Supabase",
                desc: "Database, authentication, and structured security event logging",
                icon: (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <ellipse cx="12" cy="5" rx="9" ry="3" />
                    <path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5" />
                    <path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3" />
                  </svg>
                ),
              },
              {
                name: "Arcjet",
                desc: "WAF protections, basic bot controls, and rate limiting",
                icon: (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                  </svg>
                ),
              },
              {
                name: "Vercel",
                desc: "Hardened deployments, previews, and production-like environments",
                icon: (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M2 20h20L12 4z" />
                  </svg>
                ),
              },
              {
                name: "TypeScript",
                desc: "Strict type safety across the full stack",
                icon: (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="3" width="18" height="18" rx="2" />
                    <path d="M12 8v8" />
                    <path d="M8 12h8" />
                  </svg>
                ),
              },
              {
                name: "Security Utils",
                desc: "Injection detection, sanitisation, and logging",
                icon: (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="10" />
                    <path d="M12 16v-4" />
                    <path d="M12 8h.01" />
                  </svg>
                ),
              },
            ].map((item) => (
              <div
                key={item.name}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  padding: "14px 16px",
                  borderRadius: 12,
                  background: "var(--bg-card)",
                  border: "1px solid rgba(30,41,59,0.5)",
                }}
              >
                <span style={{ color: "var(--fg-muted)", flexShrink: 0 }}>{item.icon}</span>
                <div>
                  <p style={{ margin: 0, fontWeight: 600, fontSize: 14 }}>{item.name}</p>
                  <p style={{ margin: 0, color: "var(--fg-muted)", fontSize: 12 }}>{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Team */}
        <section style={{ marginBottom: 32 }}>
          <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 10 }}>{"Team mission & collaboration"}</h2>
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 8 }}>
            Our mission is to design and deploy intelligent digital systems that are secure,
            resilient, and production-ready. We believe modern web applications must be built
            with security as a continuous lifecycle, supported by collaborative development,
            real-world testing, and measurable improvement.
          </p>
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7 }}>
            Through structured teamwork and cloud-based deployment, we transform concepts into
            defensible, operational systems that reflect professional engineering standards.
          </p>
        </section>

        {/* CTA */}
        <section style={{ marginBottom: 16 }}>
          <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 10 }}>Use this live lab as your case study</h2>
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7 }}>
            Share this site with recruiters, hiring managers, and mentors. It is a deployable,
            auditable cyber lab that demonstrates how you design, test, and improve defences —
            not just theory on a CV, but a running system that can be safely attacked, defended,
            and analysed.
          </p>
        </section>
      </main>

      {/* Footer */}
      <footer style={{ borderTop: "1px solid var(--border)", background: "var(--bg-card)" }}>
        <div
          className="container"
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr 1fr",
            gap: 40,
            paddingTop: 48,
            paddingBottom: 40,
          }}
        >
          {/* Left column - Brand */}
          <div>
            <p style={{ fontWeight: 700, fontSize: 16, marginBottom: 12 }}>Digital Twin III</p>
            <p style={{ color: "var(--fg-muted)", fontSize: 13, lineHeight: 1.7, marginBottom: 16, maxWidth: 320 }}>
              A cyber-hardened personal portfolio with integrated AI agents, real-time threat
              detection, and security analytics. Built by the DigitalMind Team.
            </p>
            {/* Social icons (decorative, not clickable) */}
            <div style={{ display: "flex", gap: 14 }}>
              {/* GitHub */}
              <span aria-label="GitHub" style={{ color: "var(--fg-muted)" }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                </svg>
              </span>
              {/* LinkedIn */}
              <span aria-label="LinkedIn" style={{ color: "var(--fg-muted)" }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
                </svg>
              </span>
              {/* Email */}
              <span aria-label="Email" style={{ color: "var(--fg-muted)" }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="2" y="4" width="20" height="16" rx="2" />
                  <path d="M22 7l-10 7L2 7" />
                </svg>
              </span>
            </div>
          </div>

          {/* Project column */}
          <div>
            <p style={{ fontWeight: 600, fontSize: 14, marginBottom: 14 }}>Project</p>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {[
                { href: "/#about", label: "About" },
                { href: "/#sandbox", label: "Projects" },
                { href: "/chat", label: "AI Agents" },
                { href: "/#team", label: "Team" },
              ].map((link) => (
                <a
                  key={link.href}
                  href={link.href}
                  style={{ color: "var(--fg-muted)", fontSize: 13, textDecoration: "none" }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = "var(--fg)")}
                  onMouseLeave={(e) => (e.currentTarget.style.color = "var(--fg-muted)")}
                >
                  {link.label}
                </a>
              ))}
            </div>
          </div>

          {/* Security column */}
          <div>
            <p style={{ fontWeight: 600, fontSize: 14, marginBottom: 14 }}>Security</p>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {[
                { href: "https://owasp.org/www-project-top-ten/", label: "OWASP", external: true },
                { href: "/#about", label: "Security Policy" },
                { href: "/#about", label: "Responsible Disclosure" },
                { href: "/dashboard", label: "Audit Logs" },
              ].map((link) => (
                <a
                  key={link.label}
                  href={link.href}
                  target={link.external ? "_blank" : undefined}
                  rel={link.external ? "noopener noreferrer" : undefined}
                  style={{ color: "var(--fg-muted)", fontSize: 13, textDecoration: "none" }}
                  onMouseEnter={(e) => (e.currentTarget.style.color = "var(--fg)")}
                  onMouseLeave={(e) => (e.currentTarget.style.color = "var(--fg-muted)")}
                >
                  {link.label}
                </a>
              ))}
            </div>
          </div>
        </div>

        {/* Copyright bar */}
        <div
          style={{
            borderTop: "1px solid var(--border)",
            padding: "16px 0",
          }}
        >
          <div
            className="container"
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              fontSize: 12,
              color: "var(--fg-muted)",
            }}
          >
            <span>{"© 2026 DigitalMind Team. All rights reserved."}</span>
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span
                style={{
                  width: 8,
                  height: 8,
                  borderRadius: "50%",
                  background: "var(--primary)",
                  display: "inline-block",
                }}
              />
              All systems operational
            </span>
          </div>
        </div>
      </footer>
    </div>
  );
}
