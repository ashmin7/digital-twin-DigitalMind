export default function LiveCyberLabPage() {
  return (
    <main
      style={{
        maxWidth: 960,
        margin: "40px auto",
        padding: 24,
        fontFamily:
          "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
        color: "#e5e7eb",
        background: "#020617",
      }}
    >
      <h1 style={{ fontSize: 28, marginBottom: 16 }}>Live Cyber Lab (Digital Twin III)</h1>
      <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 24 }}>
        A cyber-hardened personal website that behaves like a live target: inviting ethical
        attacks, detecting and blocking them in real time, and surfacing rich telemetry to
        demonstrate how I defend and continuously harden a system.
      </p>

      {/* 1. Vision and Threat Model */}
      <section style={{ marginBottom: 32 }}>
        <h2 style={{ fontSize: 20, marginBottom: 8 }}>1. Vision and Threat Model</h2>
        <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 12 }}>
          The Live Cyber Lab is my Digital Twin: a cyber-hardened version of my professional
          identity that is intentionally exposed to controlled attacks. Instead of a static,
          brochure-style portfolio, this Digital Twin behaves like a production web application
          under fireinstrumented so that attacks become evidence of my security practice, not
          weaknesses to exploit.
        </p>
        <h3 style={{ fontSize: 16, marginBottom: 6 }}>From Portfolio to Digital Twin</h3>
        <ul style={{ color: "#9ca3af", fontSize: 14, paddingLeft: 20, marginBottom: 12 }}>
          <li>Hosts my public identity and real security projects</li>
          <li>Exposes deliberate attack surfaces (SQLi, XSS, auth flows, chatbot APIs)</li>
          <li>Implements real detection, blocking, and logging behind the scenes</li>
          <li>Surfaces telemetry through a Security Dashboard and evidence documents</li>
        </ul>
        <h3 style={{ fontSize: 16, marginBottom: 6 }}>Threat Model</h3>
        <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 8 }}>
          The lab is explicitly designed to withstand and showcase defences against:
        </p>
        <ul style={{ color: "#9ca3af", fontSize: 14, paddingLeft: 20 }}>
          <li>
            <strong>SQL Injection</strong>: union-based payloads, boolean tautologies, stacked
            queries, and schema enumeration attempts aimed at manipulating database queries.
          </li>
          <li>
            <strong>Prompt Injection</strong>: attempts to override system prompts, exfiltrate
            hidden instructions, or bypass safety constraints in the chatbot.
          </li>
          <li>
            <strong>Automated Bot &amp; Scanner Attacks</strong>: high-frequency scripted
            requests, endpoint enumeration, and brute-force style behaviour.
          </li>
          <li>
            <strong>XSS &amp; Malicious Payloads</strong>: script injection, event-handler abuse,
            and crafted HTML/JS inputs.
          </li>
          <li>
            <strong>Authentication &amp; Access-Control Failures</strong>: broken access control
            and privilege-abuse scenarios.
          </li>
        </ul>
      </section>

      {/* 2. Secure Architecture & Defensive Layers */}
      <section style={{ marginBottom: 32 }}>
        <h2 style={{ fontSize: 20, marginBottom: 8 }}>2. Secure Architecture &amp; Defensive Layers</h2>
        <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 12 }}>
          The Live Cyber Lab is structured as a layered defensive architecture, mirroring a
          modern production-grade web stack.
        </p>
        <h3 style={{ fontSize: 16, marginBottom: 6 }}>Secure Application &amp; CMS Foundations</h3>
        <ul style={{ color: "#9ca3af", fontSize: 14, paddingLeft: 20, marginBottom: 12 }}>
          <li>
            <strong>Next.js (App Router) + TypeScript</strong>: clear separation of public pages,
            APIs, and admin-like endpoints with strong typing.
          </li>
          <li>
            <strong>Managed Postgres (via Supabase)</strong>: structured content tables
            (projects, posts) and a dedicated <code>security_events</code> table for audit logs.
          </li>
          <li>
            <strong>Authentication &amp; Access Control</strong>: protected admin-style endpoints
            that demonstrate both correct and incorrect access patterns.
          </li>
        </ul>
        <h3 style={{ fontSize: 16, marginBottom: 6 }}>Defensive Controls: WAF, Firewalls, Detection</h3>
        <ul style={{ color: "#9ca3af", fontSize: 14, paddingLeft: 20 }}>
          <li>
            Rule-based detectors for SQLi, XSS, and prompt injection, classifying threats as
            <code>SQL_INJECTION</code>, <code>MALICIOUS_PAYLOAD</code>,
            <code>PROMPT_INJECTION</code>, and more.
          </li>
          <li>
            Per-IP, per-endpoint rate limiting on chatbot and sandbox APIs, logging
            <code>BOT_BEHAVIOR</code> and <code>RATE_LIMITED</code> events to simulate
            WAF/firewall behaviour.
          </li>
          <li>
            AI-aware safety on the chatbot: prompt-injection detection and refusal to execute
            harmful instructions.
          </li>
        </ul>
      </section>

      {/* 3. Threat Telemetry Dashboard */}
      <section style={{ marginBottom: 32 }}>
        <h2 style={{ fontSize: 20, marginBottom: 8 }}>3. Threat Telemetry Dashboard</h2>
        <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 12 }}>
          At the heart of the Live Cyber Lab is an Ethical Hacking Zone and a Threat Telemetry
          Dashboard that turns hostile activity into actionable insight.
        </p>
        <h3 style={{ fontSize: 16, marginBottom: 6 }}>Ethical Hacking Zone</h3>
        <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 8 }}>
          Public sandbox routes invite safe experimentation:
        </p>
        <ul style={{ color: "#9ca3af", fontSize: 14, paddingLeft: 20, marginBottom: 12 }}>
          <li><code>/sandbox/sql</code>  SQL injection payloads and server-side detection.</li>
          <li>
            <code>/sandbox/xss</code>  XSS / malicious payload detection and sanitisation.
          </li>
          <li>
            <code>/sandbox/auth</code>  authentication and access-control misbehaviour.
          </li>
          <li>
            <code>/sandbox/rate-limit</code>  high-frequency / bot-style traffic.
          </li>
        </ul>
        <h3 style={{ fontSize: 16, marginBottom: 6 }}>Dashboard &amp; Behaviour Analysis</h3>
        <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 8 }}>
          A dedicated dashboard aggregates <code>security_events</code> for the last 24 hours,
          showing:
        </p>
        <ul style={{ color: "#9ca3af", fontSize: 14, paddingLeft: 20 }}>
          <li>Total events and blocked vs allowed/challenged actions.</li>
          <li>
            Threat counts by type (SQL injection, prompt injection, malicious payloads,
            auth failures, bot behaviour).
          </li>
          <li>
            Time-ordered activity with endpoint, severity, and source IP for attacker
            behaviour analysis.
          </li>
        </ul>
      </section>

      {/* 4. Evidence of Resilience */}
      <section style={{ marginBottom: 32 }}>
        <h2 style={{ fontSize: 20, marginBottom: 8 }}>4. Evidence of Resilience</h2>
        <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 8 }}>
          Beyond blocking attacks, the lab is supported by technical evidence that documents how
          findings are assessed and resolved over time. This includes, for each major threat
          category:
        </p>
        <ul style={{ color: "#9ca3af", fontSize: 14, paddingLeft: 20 }}>
          <li>CVSS scoring sheets with rationale for each vector.</li>
          <li>Risk reports summarising likelihood, impact, and residual risk.</li>
          <li>Penetration test summaries and red-team style attack notes.</li>
          <li>
            Remediation notes and hardening history linked back to specific telemetry or test
            results.
          </li>
        </ul>
      </section>

      {/* 5. Security as a Lifecycle */}
      <section>
        <h2 style={{ fontSize: 20, marginBottom: 8 }}>5. Security as a Lifecycle</h2>
        <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 8 }}>
          The most important outcome of this project is not a single \"secure release\" but the
          demonstration of security as an ongoing lifecycle.
        </p>
        <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 8 }}>
          The lab follows a continuous loop: expose and attract (via safe sandboxes), detect and
          observe (through rich logging), assess and prioritise (using CVSS and risk analysis),
          respond and harden (by tightening rules and architecture), and document and
          communicate (through reports and evidence).
        </p>
        <p style={{ color: "#9ca3af", fontSize: 14 }}>
          By running this Digital Twin in the open, I demonstrate that I can design defensible
          architectures, operate a system under real-world pressure, and improve security over
          time. This Live Cyber Lab is not only a portfolio; it is a practical demonstration of
          how I think and work as a cyber security professional.
        </p>
      </section>
    </main>
  );
}
