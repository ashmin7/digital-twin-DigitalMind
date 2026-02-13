export default function SandboxLandingPage() {
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
      <h1 style={{ fontSize: 28, marginBottom: 16 }}>Hacking simulation sandbox</h1>
      <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 12 }}>
        These live sandboxes are wired to real detection, logging, and rate limiting. You can
        safely try common attacks and immediately see how the application reacts.
      </p>
      <ul style={{ fontSize: 14, paddingLeft: 20 }}>
        <li style={{ marginBottom: 6 }}>
          <a href="/sandbox/sql" style={{ color: "#38bdf8" }}>
            /sandbox/sql
          </a>{" "}
           SQL injection payloads, detection, and safe query patterns.
        </li>
        <li style={{ marginBottom: 6 }}>
          <a href="/sandbox/xss" style={{ color: "#38bdf8" }}>
            /sandbox/xss
          </a>{" "}
           reflected XSS attempts, output encoding, and malicious payload detection.
        </li>
        <li style={{ marginBottom: 6 }}>
          <a href="/sandbox/rate-limit" style={{ color: "#38bdf8" }}>
            /sandbox/rate-limit
          </a>{" "}
           automated/bot-style traffic, scanners, and basic WAF-style rate limiting.
        </li>
        <li style={{ marginBottom: 6 }}>
          <a href="/sandbox/auth" style={{ color: "#38bdf8" }}>
            /sandbox/auth
          </a>{" "}
           authentication failures, broken access control, and privilege-abuse scenarios.
        </li>
      </ul>
      <p style={{ color: "#9ca3af", fontSize: 14, marginTop: 12 }}>
        Use this page as the entry point when inviting people to attack the lab; from here they
        can choose which surface to exercise.
      </p>
    </main>
  );
}
