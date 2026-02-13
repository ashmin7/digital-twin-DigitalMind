import { getSupabaseServer } from "../../lib/supabase-server";

interface SecurityEventRow {
  id: string;
  event_type: string;
  severity: string;
  threat_type: string | null;
  action: string;
  endpoint: string;
  source_ip: string | null;
  user_agent: string | null;
  timestamp: string;
  metadata?: any | null;
}

function groupBy<T, K extends string | number | symbol>(items: T[], getKey: (item: T) => K) {
  return items.reduce((acc, item) => {
    const key = getKey(item);
    // @ts-ignore
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {} as Record<K, number>);
}

export default async function DashboardPage() {
  const supabase = getSupabaseServer();

  if (!supabase) {
    return (
      <main style={{ maxWidth: 960, margin: "40px auto", padding: 24 }}>
        <h1>Security Dashboard</h1>
        <p style={{ color: "#555" }}>
          Supabase is not configured. Set <code>NEXT_PUBLIC_SUPABASE_URL</code> and
          {" "}
          <code>SUPABASE_SERVICE_KEY</code> and run the migration in
          {" "}
          <code>migrations/001_security_events.sql</code> to enable telemetry.
        </p>
      </main>
    );
  }

  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const { data, error } = await supabase
    .from("security_events")
    .select(
      "id, event_type, severity, threat_type, action, endpoint, source_ip, user_agent, timestamp, metadata"
    )
    .gte("timestamp", since)
    .order("timestamp", { ascending: false })
    .limit(100);

  if (error) {
    console.error("Error loading security_events", error);
  }

  const events: SecurityEventRow[] = (data as any) || [];

  const threatsByType = groupBy(events, (e) => e.threat_type || "UNKNOWN");
  const actions = groupBy(events, (e) => e.action);

  const blocked = actions["BLOCK"] || 0;
  const allowed = (actions["ALLOW"] || 0) + (actions["CHALLENGE"] || 0);
  const rateLimited = events.filter((e) => e.event_type === "RATE_LIMITED").length;
  const botDetections = events.filter((e) => e.threat_type === "BOT_BEHAVIOR").length;
  const shieldTriggers = events.filter((e) => e.event_type === "THREAT_DETECTED").length;
  const uniqueIps = new Set(events.map((e) => e.source_ip).filter(Boolean)).size;

  const arcjetEvents = events.filter((e) => e.metadata && e.metadata.provider === "arcjet");
  const arcjetBlocks = arcjetEvents.filter((e) => e.action === "BLOCK").length;
  const arcjetRateLimits = arcjetEvents.filter((e) => e.event_type === "RATE_LIMITED").length;
  const arcjetBots = arcjetEvents.filter(
    (e) => e.threat_type === "BOT_BEHAVIOR" || (e.metadata && e.metadata.kind?.includes("bot"))
  ).length;

  const activeAlerts = events.filter((e) => e.severity === "HIGH" || e.severity === "CRITICAL");

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#020617",
        color: "#e5e7eb",
        fontFamily: "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif",
      }}
    >
      <main style={{ maxWidth: 1040, margin: "0 auto", padding: "32px 24px 40px" }}>
        <header
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 24,
          }}
        >
          <div>
            <p style={{ fontSize: 12, letterSpacing: 2, textTransform: "uppercase", color: "#a5b4fc" }}>
              Digital Twin III
            </p>
            <h1 style={{ fontSize: 24, margin: "4px 0" }}>Security Dashboard</h1>
            <p style={{ fontSize: 13, color: "#9ca3af" }}>
              Real-time security telemetry from your live cyber lab over the last 24 hours.
            </p>
          </div>
          <a
            href="/"
            style={{
              padding: "8px 14px",
              borderRadius: 999,
              border: "1px solid #334155",
              fontSize: 13,
              color: "#e5e7eb",
              textDecoration: "none",
            }}
          >
            ← Back to site
          </a>
        </header>

        {/* Overview cards */}
        <section style={{ marginBottom: 24 }}>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
              gap: 12,
            }}
          >
            <MetricCard label="Total requests" value={events.length} description="Events logged (24h)" />
            <MetricCard label="Allowed" value={allowed} description="Safe or challenged" accent="#22c55e" />
            <MetricCard label="Blocked" value={blocked} description="High-risk stopped" accent="#ef4444" />
            <MetricCard label="Rate limits" value={rateLimited} description="Excessive traffic" accent="#eab308" />
            <MetricCard label="Bot detections" value={botDetections} description="Automated behaviour" accent="#38bdf8" />
            <MetricCard label="Shield triggers" value={shieldTriggers} description="Threat detections" accent="#8b5cf6" />
            <MetricCard label="Unique IPs" value={uniqueIps} description="Distinct sources" accent="#f97316" />
          </div>
        </section>

        {/* Arcjet-specific view */}
        <section style={{ marginBottom: 24 }}>
          <h2 style={{ fontSize: 16, marginBottom: 8 }}>Arcjet edge protection</h2>
          {arcjetEvents.length === 0 ? (
            <p style={{ fontSize: 13, color: "#9ca3af" }}>
              No Arcjet decisions have been logged in the last 24 hours yet. Generate traffic
              against the sandbox APIs or run basic scans to see edge firewall activity here.
            </p>
          ) : (
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
                gap: 12,
              }}
            >
              <MetricCard
                label="Arcjet blocks"
                value={arcjetBlocks}
                description="Requests stopped at the edge"
                accent="#f97316"
              />
              <MetricCard
                label="Arcjet rate limits"
                value={arcjetRateLimits}
                description="Throttled abusive traffic"
                accent="#eab308"
              />
              <MetricCard
                label="Arcjet bot denials"
                value={arcjetBots}
                description="Bots and spoofed clients blocked"
                accent="#38bdf8"
              />
            </div>
          )}
        </section>

        {/* Threat mix */}
        <section style={{ marginBottom: 24 }}>
          <h2 style={{ fontSize: 16, marginBottom: 8 }}>Threat mix (last 24 hours)</h2>
          {events.length === 0 ? (
            <p style={{ fontSize: 13, color: "#9ca3af" }}>
              No telemetry yet. Use the sandbox endpoints and security tools to generate
              real attack traffic, then refresh this page.
            </p>
          ) : (
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: 8,
              }}
            >
              {Object.entries(threatsByType).map(([type, count]) => (
                <div
                  key={type}
                  style={{
                    padding: "6px 10px",
                    borderRadius: 999,
                    border: "1px solid #1f2937",
                    background: "#020617",
                    fontSize: 12,
                    color: "#e5e7eb",
                  }}
                >
                  <span style={{ opacity: 0.75 }}>{type}</span>
                  <span style={{ marginLeft: 8, color: "#a5b4fc" }}>×{count}</span>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Active alerts */}
        <section style={{ marginBottom: 24 }}>
          <h2 style={{ fontSize: 16, marginBottom: 8 }}>Active alerts</h2>
          <div
            style={{
              borderRadius: 16,
              border: "1px solid #1f2937",
              background: "#020617",
              padding: 16,
            }}
          >
            {activeAlerts.length === 0 ? (
              <p style={{ fontSize: 13, color: "#9ca3af" }}>
                No active security alerts. Your application is stable under current traffic.
              </p>
            ) : (
              <ul style={{ listStyle: "none", padding: 0, margin: 0, fontSize: 13 }}>
                {activeAlerts.map((e) => (
                  <li
                    key={e.id}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      padding: "8px 0",
                      borderBottom: "1px solid #111827",
                    }}
                  >
                    <div>
                      <div>
                        <strong>{e.severity}</strong> · {e.threat_type || e.event_type}
                      </div>
                      <div style={{ color: "#9ca3af" }}>
                        {e.endpoint} · {new Date(e.timestamp).toLocaleString()}
                      </div>
                    </div>
                    <div style={{ fontSize: 12, color: "#9ca3af" }}>{e.source_ip || "-"}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        {/* Recent activity table */}
        <section style={{ marginBottom: 24 }}>
          <h2 style={{ fontSize: 16, marginBottom: 8 }}>Recent activity</h2>
          {events.length === 0 ? (
            <p style={{ fontSize: 13, color: "#9ca3af" }}>No recent events.</p>
          ) : (
            <div
              style={{
                borderRadius: 16,
                border: "1px solid #1f2937",
                overflow: "hidden",
                background: "#020617",
              }}
            >
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                <thead style={{ background: "#020617" }}>
                  <tr>
                    <th style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #111827" }}>
                      Time
                    </th>
                    <th style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #111827" }}>
                      Type
                    </th>
                    <th style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #111827" }}>
                      Severity
                    </th>
                    <th style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #111827" }}>
                      Action
                    </th>
                    <th style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #111827" }}>
                      Endpoint
                    </th>
                    <th style={{ textAlign: "left", padding: 8, borderBottom: "1px solid #111827" }}>
                      IP
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id}>
                      <td style={{ padding: 8, borderBottom: "1px solid #111827" }}>
                        {new Date(e.timestamp).toLocaleString()}
                      </td>
                      <td style={{ padding: 8, borderBottom: "1px solid #111827" }}>
                        {e.threat_type || e.event_type}
                      </td>
                      <td style={{ padding: 8, borderBottom: "1px solid #111827" }}>{e.severity}</td>
                      <td style={{ padding: 8, borderBottom: "1px solid #111827" }}>{e.action}</td>
                      <td style={{ padding: 8, borderBottom: "1px solid #111827" }}>{e.endpoint}</td>
                      <td style={{ padding: 8, borderBottom: "1px solid #111827" }}>{e.source_ip || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Evidence link */}
        <section>
          <h2 style={{ fontSize: 16, marginBottom: 8 }}>Evidence & reports</h2>
          <p style={{ fontSize: 13, color: "#9ca3af" }}>
            Detailed logs, risk assessments, and remediation notes are maintained in
            {" "}
            <a
              href="https://github.com/ashmin7/digital-twin-DigitalMind/blob/main/docs/security-evidence.md"
              target="_blank"
              rel="noreferrer"
              style={{ color: "#38bdf8" }}
            >
              docs/security-evidence.md
            </a>
            . Use that file to capture screenshots, exported scan reports, and structured
            summaries for each security layer.
          </p>
        </section>
      </main>
    </div>
  );
}

interface MetricCardProps {
  label: string;
  value: number;
  description: string;
  accent?: string;
}

function MetricCard({ label, value, description, accent = "#38bdf8" }: MetricCardProps) {
  return (
    <div
      style={{
        borderRadius: 16,
        padding: 12,
        border: "1px solid #1f2937",
        background: "linear-gradient(135deg, rgba(56,189,248,0.12), rgba(15,23,42,0.95))",
      }}
    >
      <div style={{ fontSize: 12, color: "#9ca3af", marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 600, color: accent }}>{value}</div>
      <div style={{ fontSize: 12, color: "#9ca3af" }}>{description}</div>
    </div>
  );
}
