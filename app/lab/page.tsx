export default function LiveCyberLabPage() {
  return (
    <div className="cyber-bg">
      <main className="container-md" style={{ paddingTop: 40, paddingBottom: 40 }}>
        <a href="/" style={{ fontSize: 13, display: "inline-block", marginBottom: 16 }}>
          {"<- Back to site"}
        </a>
        <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 16 }}>
          Digital Twin III — Cyber-Hardened Portfolio
        </h1>
        <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 16 }}>
          <strong style={{ color: "var(--fg)" }}>Hack us if you can.</strong> This portfolio is no longer just a showcase of
          work — it is a monitored, security-aware web system designed to run under real-world conditions.
        </p>
        <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 16 }}>
          Modern professional web applications are active targets. Systems that manage data,
          users, and AI-driven features must be built to defend, monitor, and continuously
          improve their resilience. This project transforms our portfolio into a cyber-secured,
          intelligence-driven digital platform that demonstrates practical security
          implementation rather than theoretical claims.
        </p>
        <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 24 }}>
          Developed as a collaborative initiative within an industry-aligned program delivered by
          <strong style={{ color: "var(--fg)" }}> ausbiz Consulting</strong>, this project focuses on building a production-ready
          web application capable of detecting threats, protecting data, and demonstrating
          defensive system design.
        </p>

        <Section title="From Portfolio to Secure Digital System">
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 8 }}>
            Our team designed and deployed a portfolio platform that integrates security
            controls, monitoring mechanisms, and layered defensive architecture to address common
            web application vulnerabilities. Security considerations include protection against:
          </p>
          <ul style={{ color: "var(--fg-muted)", fontSize: 14, paddingLeft: 20, display: "flex", flexDirection: "column", gap: 4 }}>
            <li>SQL injection attacks</li>
            <li>Prompt injection and other malicious inputs</li>
            <li>Authentication and authorization weaknesses</li>
            <li>Broken access control</li>
            <li>{"Malicious payload execution (e.g., XSS)"}</li>
            <li>Automated bot activity and suspicious traffic behaviour</li>
          </ul>
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginTop: 8 }}>
            Rather than treating security as a static feature, the system operates as a live
            cyber environment: traffic is exercised using common testing tools, logged into
            Supabase, surfaced through the dashboard, and used to drive regular hardening changes.
          </p>
        </Section>

        <Section title="Evidence-Based Security Approach">
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 8 }}>
            The project emphasises measurable and observable security practices. The platform supports:
          </p>
          <ul style={{ color: "var(--fg-muted)", fontSize: 14, paddingLeft: 20, display: "flex", flexDirection: "column", gap: 4 }}>
            <li>System activity logging and monitoring</li>
            <li>Threat detection and attacker behaviour analysis</li>
            <li>Risk awareness and defensive configuration tuning</li>
            <li>Documentation of system refinement and improvements over time</li>
            <li>Continuous system hardening through iterative development and retesting</li>
          </ul>
        </Section>

        <Section title="What This Project Demonstrates">
          <ul style={{ color: "var(--fg-muted)", fontSize: 14, paddingLeft: 20, display: "flex", flexDirection: "column", gap: 4 }}>
            <li>Hosts professional identity and project work in a security-focused environment</li>
            <li>Implements defensive controls within a real cloud deployment</li>
            <li>Demonstrates awareness of modern cybersecurity risks and attack patterns</li>
            <li>Applies security as an ongoing lifecycle practice, not a one-off task</li>
            <li>Reflects real-world development, observability, and deployment standards</li>
          </ul>
        </Section>

        <Section title="Security as a Lifecycle">
          <ol style={{ color: "var(--fg-muted)", fontSize: 14, paddingLeft: 20, display: "flex", flexDirection: "column", gap: 8 }}>
            <li><strong style={{ color: "var(--fg)" }}>Prevent</strong> — Arcjet acts as a WAF and rate limiter at the edge, while input validation, output encoding, and role-based access control harden the application.</li>
            <li><strong style={{ color: "var(--fg)" }}>Detect</strong> — Custom detectors flag SQL injection, XSS, prompt injection, auth failures, and bot behaviour. Every event is written to Supabase as structured telemetry.</li>
            <li><strong style={{ color: "var(--fg)" }}>Respond</strong> — The security dashboard highlights active alerts and recent incidents so an operator can quickly see what was blocked, from where, and why.</li>
            <li><strong style={{ color: "var(--fg)" }}>Improve</strong> — Attack patterns from logs and Arcjet are used to tighten rules, tune rate limits, add new detectors, and update this case study with evidence.</li>
          </ol>
        </Section>

        <Section title="Project Vision">
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 8 }}>
            This project is more than a portfolio — it is a deployable, auditable demonstration of
            secure web development practice. It reflects our ability to design systems that are
            not only functional and scalable, but also resilient and professionally defensible.
          </p>
          <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7 }}>
            Digital Twin III represents a system designed not just to function, but to withstand.
          </p>
        </Section>
      </main>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section style={{ marginBottom: 32 }}>
      <h2 style={{ fontSize: 20, fontWeight: 600, marginBottom: 10 }}>{title}</h2>
      {children}
    </section>
  );
}
