export default function ThreatsPage() {
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
      <h1 style={{ fontSize: 28, marginBottom: 16 }}>Threats you train against</h1>
      <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 16 }}>
        This lab is designed around the most common and high-impact web application threats.
        Each category is instrumented so you can attack it safely and see how the system
        responds.
      </p>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
          gap: 16,
          fontSize: 14,
        }}
      >
        <div style={{ padding: 12, borderRadius: 12, border: "1px solid #1f2937" }}>
          <h2 style={{ fontSize: 16, marginBottom: 6 }}>Injection attacks</h2>
          <p style={{ color: "#9ca3af" }}>
            SQL injection, prompt injection, and malicious payloads targeting data stores,
            interpreters, or AI models.
          </p>
        </div>
        <div style={{ padding: 12, borderRadius: 12, border: "1px solid #1f2937" }}>
          <h2 style={{ fontSize: 16, marginBottom: 6 }}>Auth &amp; access control</h2>
          <p style={{ color: "#9ca3af" }}>
            Authentication failures, broken access control, and privilege abuse scenarios across
            sandbox endpoints and admin surfaces.
          </p>
        </div>
        <div style={{ padding: 12, borderRadius: 12, border: "1px solid #1f2937" }}>
          <h2 style={{ fontSize: 16, marginBottom: 6 }}>Bots &amp; automation</h2>
          <p style={{ color: "#9ca3af" }}>
            Automated scanners, brute force tools, scripted requests, and spoofed user agents
            detected and rate-limited at the edge.
          </p>
        </div>
      </div>
      <p style={{ color: "#9ca3af", fontSize: 14, marginTop: 16 }}>
        Combined with the security dashboard, this page helps you explain exactly what kinds of
        behaviour your system is meant to withstand.
      </p>
    </main>
  );
}
