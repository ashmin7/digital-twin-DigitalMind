"use client";

export default function Home() {
  const rollDice = () => {
    const result = Math.floor(Math.random() * 6) + 1;
    alert("You rolled: " + result);
  };
  return (
    <main style={{
      maxWidth: 960,
      margin: "40px auto",
      padding: 24,
      fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
      lineHeight: 1.6
    }}>
      <h1 style={{ marginBottom: 8 }}>Cybersecurity Engineer Portfolio</h1>
      <p style={{ color: "#555", marginBottom: 24 }}>
        A modern portfolio showcasing secure web engineering, AI security agents, and a live
        hacking simulation sandbox.
      </p>

      <section
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: 16,
          marginTop: 8,
          marginBottom: 32,
        }}
      >
        <div style={{ flex: 1 }}>
          <h2 style={{ marginTop: 0 }}>About</h2>
          <p>
            This digital twin highlights practical security skills: building hardened web flows,
            detecting common attacks, and explaining security decisions clearly to both engineers
            and non-technical stakeholders.
          </p>
        </div>
        <div
          style={{
            flex: 1,
            textAlign: "center",
            padding: 16,
            border: "1px solid #eee",
            borderRadius: 8,
          }}
        >
          <h2 style={{ margin: 0 }}>Live Demo</h2>
          <p style={{ marginTop: 8 }}>Deployed on Vercel and ready for recruiters and reviewers.</p>
          <button
            onClick={rollDice}
            style={{ marginTop: 12, padding: "8px 12px", cursor: "pointer", borderRadius: 6 }}
          >
            Roll Dice 🎲 <span style={{ fontSize: 12, marginLeft: 4 }}>(tool example)</span>
          </button>
        </div>
      </section>

      <section style={{ marginTop: 16 }}>
        <h2>Featured Capabilities</h2>
        <ul>
          <li>Hacking simulation sandbox for SQL injection, XSS, and rate limiting.</li>
          <li>AI-powered agents for threat detection, analytics, and content generation.</li>
          <li>Structured security logging and a planned real-time dashboard.</li>
        </ul>
      </section>

      <section style={{ marginTop: 24 }}>
        <h2>Sandbox</h2>
        <p style={{ color: "#555" }}>Safe, isolated routes to experiment with typical web attacks:</p>
        <ul>
          <li><a href="/sandbox/sql">/sandbox/sql</a> — SQL injection scenarios.</li>
          <li><a href="/sandbox/xss">/sandbox/xss</a> — XSS and output encoding.</li>
          <li><a href="/sandbox/rate-limit">/sandbox/rate-limit</a> — Rate limiting behavior.</li>
        </ul>
      </section>

      <section style={{ marginTop: 24 }}>
        <h2>Tech Stack</h2>
        <ul>
          <li>Next.js (App Router) + TypeScript</li>
          <li>Supabase (database, auth, audit logs)</li>
          <li>ArcJet (threat detection, rate limiting)</li>
          <li>OpenAI (security and persona agents)</li>
          <li>Vercel (hosting & CI/CD)</li>
        </ul>
      </section>

      <section style={{ marginTop: 24, marginBottom: 16 }}>
        <h2>Contact</h2>
        <p>
          Use this portfolio as a live example during interviews or screenings. You can link
          directly to this site from your resume, LinkedIn, or GitHub profile.
        </p>
      </section>
    </main>
  );
}
