export default function AboutPage() {
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
      <h1 style={{ fontSize: 28, marginBottom: 16 }}>About this Digital Twin</h1>
      <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 12 }}>
        Every production web app is a target. This Digital Twin turns that risk into a teaching
        tool: a controlled cyber range where you can deliberately attack, observe detections and
        blocks, practise incident response, and document how you harden the system release by
        release.
      </p>
      <p style={{ color: "#9ca3af", fontSize: 14, marginBottom: 12 }}>
        For hiring managers, this site is both a portfolio and a live security case study: it
        hosts my professional identity and projects, exposes safe attack surfaces, and shows how
        I manage security as an ongoing lifecycle instead of a one-time checkbox.
      </p>
      <p style={{ color: "#9ca3af", fontSize: 14 }}>
        Use this page to understand the intent behind the lab, how it was built, and how it fits
        into real-world expectations for secure, observable web systems.
      </p>
    </main>
  );
}
