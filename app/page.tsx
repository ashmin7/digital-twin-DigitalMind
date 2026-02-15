"use client";

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
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span className="glow-dot" />
            <span style={{ fontWeight: 600, fontSize: 15 }}>Digital Twin III</span>
          </div>
          <nav style={{ display: "flex", gap: 16, fontSize: 13 }}>
            {[
              { href: "/#about", label: "About" },
              { href: "/#sandbox", label: "Sandbox" },
              { href: "/#threats", label: "Threats" },
              { href: "/#stack", label: "Stack" },
              { href: "/lab", label: "Lab Case Study" },
              { href: "/dashboard", label: "Dashboard" },
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

          {/* Right card */}
          <div
            style={{
              flexBasis: 290,
              flexGrow: 0,
              flexShrink: 0,
              borderRadius: 20,
              padding: 18,
              background: "radial-gradient(circle at top, rgba(56,189,248,0.25), transparent 60%), var(--bg-card)",
              border: "1px solid rgba(30,41,59,0.5)",
              display: "flex",
              flexDirection: "column",
              gap: 14,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <p style={{ fontSize: 11, color: "var(--accent)", margin: 0 }}>Live Lab</p>
                <p style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>Attack surface summary</p>
              </div>
              <span className="badge badge-online">Online</span>
            </div>
            <div style={{ borderRadius: 14, background: "rgba(11,18,37,0.9)", padding: 14, fontSize: 13 }}>
              <ul style={{ margin: 0, paddingLeft: 18 }}>
                <li>Target SQL injection, XSS, and auth flows in safe sandboxes.</li>
                <li style={{ marginTop: 4 }}>Every attempt is logged into the Supabase-backed security dashboard.</li>
                <li style={{ marginTop: 4 }}>Use your own testing tools and payloads — this lab is built to be attacked.</li>
              </ul>
            </div>
            <a
              href="/dashboard"
              className="btn-outline"
              style={{ marginTop: "auto", display: "flex", justifyContent: "space-between", fontSize: 12 }}
            >
              <span>Open security dashboard</span>
              <span>{">"}</span>
            </a>
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
          <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 10 }}>Hacking simulation sandbox</h2>
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7 }}>
            These live sandboxes are wired to real detection, logging, and rate limiting. You can
            safely try common attacks and then open the dashboard to observe how the system
            classified and handled your traffic.
          </p>
          <ul style={{ fontSize: 14, marginTop: 14, listStyle: "none", padding: 0, display: "flex", flexDirection: "column", gap: 8 }}>
            {[
              { href: "/sandbox/sql", label: "/sandbox/sql", desc: " — SQL injection payloads, detection, and safe query patterns." },
              { href: "/sandbox/xss", label: "/sandbox/xss", desc: " — reflected XSS attempts, output encoding, and malicious payload detection." },
              { href: "/sandbox/rate-limit", label: "/sandbox/rate-limit", desc: " — automated/bot-style traffic, scanners, and basic WAF-style rate limiting." },
              { href: "/sandbox/auth", label: "/sandbox/auth", desc: " — authentication failures, broken access control, and privilege-abuse scenarios." },
            ].map((s) => (
              <li key={s.href}>
                <a href={s.href} style={{ color: "var(--accent)" }}>{s.label}</a>
                <span style={{ color: "var(--fg-muted)" }}>{s.desc}</span>
              </li>
            ))}
          </ul>
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
    </div>
  );
}
