export default function ThreatsPage() {
  const threats = [
    {
      title: "Injection attacks",
      desc: "SQL injection, prompt injection, and malicious payloads targeting data stores, interpreters, or AI models.",
    },
    {
      title: "Auth & access control",
      desc: "Authentication failures, broken access control, and privilege abuse scenarios across sandbox endpoints and admin surfaces.",
    },
    {
      title: "Bots & automation",
      desc: "Automated scanners, brute force tools, scripted requests, and spoofed user agents detected and rate-limited at the edge.",
    },
  ];

  return (
    <div className="cyber-bg">
      <main className="container-md" style={{ paddingTop: 40, paddingBottom: 40 }}>
        <a href="/" style={{ fontSize: 13, display: "inline-block", marginBottom: 16 }}>
          {"<- Back to site"}
        </a>
        <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 16 }}>Threats you train against</h1>
        <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 24 }}>
          This lab is designed around the most common and high-impact web application threats.
          Each category is instrumented so you can attack it safely and see how the system responds.
        </p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16 }}>
          {threats.map((t) => (
            <div key={t.title} className="link-card">
              <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>{t.title}</h2>
              <p style={{ color: "var(--fg-muted)", fontSize: 13, lineHeight: 1.6, margin: 0 }}>{t.desc}</p>
            </div>
          ))}
        </div>
        <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginTop: 24 }}>
          Combined with the security dashboard, this page helps you explain exactly what kinds of
          behaviour your system is meant to withstand.
        </p>
      </main>
    </div>
  );
}
