export default function StackPage() {
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
      <h1 style={{ fontSize: 28, marginBottom: 16 }}>Security-focused tech stack</h1>
      <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 12 }}>
        The Digital Twin lab is built with a modern, production-ready stack that emphasises
        observability and defence-in-depth.
      </p>
      <ul style={{ fontSize: 14, color: "#e5e7eb", paddingLeft: 20 }}>
        <li>
          Next.js (App Router) + TypeScript for a modern, testable, security-first frontend and
          API surface.
        </li>
        <li>Supabase for database, authentication, and structured security event logging.</li>
        <li>Arcjet for WAF protections, basic bot controls, and rate limiting at the edge.</li>
        <li>Security utility functions for injection detection, sanitisation, and logging.</li>
        <li>Vercel for hardened deployments, previews, and production-like environments.</li>
      </ul>
      <p style={{ color: "#9ca3af", fontSize: 14, marginTop: 12 }}>
        This combination lets you talk concretely about how you build, deploy, and operate a
        secure web system in the cloud.
      </p>
    </main>
  );
}
