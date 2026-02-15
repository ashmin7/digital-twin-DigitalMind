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
  metadata?: Record<string, unknown> | null;
}

function groupBy<T, K extends string | number | symbol>(items: T[], getKey: (item: T) => K) {
  return items.reduce(
    (acc, item) => {
      const key = getKey(item);
      (acc as Record<K, number>)[key] = ((acc as Record<K, number>)[key] || 0) + 1;
      return acc;
    },
    {} as Record<K, number>,
  );
}

export default async function DashboardPage() {
  const supabase = getSupabaseServer();

  if (!supabase) {
    return (
      <div className="cyber-bg">
        <main className="container-md" style={{ paddingTop: 40, paddingBottom: 40 }}>
          <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 16 }}>Security Dashboard</h1>
          <p style={{ color: "var(--fg-muted)", fontSize: 14 }}>
            Supabase is not configured. Set{" "}
            <code style={{ color: "var(--accent)", fontFamily: "var(--font-mono)", fontSize: 12 }}>NEXT_PUBLIC_SUPABASE_URL</code>{" "}
            and{" "}
            <code style={{ color: "var(--accent)", fontFamily: "var(--font-mono)", fontSize: 12 }}>SUPABASE_SERVICE_KEY</code>{" "}
            to enable telemetry.
          </p>
        </main>
      </div>
    );
  }

  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const { data, error } = await supabase
    .from("security_events")
    .select("id, event_type, severity, threat_type, action, endpoint, source_ip, user_agent, timestamp, metadata")
    .gte("timestamp", since)
    .order("timestamp", { ascending: false })
    .limit(100);

  if (error) console.error("Error loading security_events", error);

  const events: SecurityEventRow[] = (data as SecurityEventRow[]) || [];
  const threatsByType = groupBy(events, (e) => e.threat_type || "UNKNOWN");
  const actions = groupBy(events, (e) => e.action);
  const blocked = actions["BLOCK"] || 0;
  const allowed = (actions["ALLOW"] || 0) + (actions["CHALLENGE"] || 0);
  const rateLimited = events.filter((e) => e.event_type === "RATE_LIMITED").length;
  const botDetections = events.filter((e) => e.threat_type === "BOT_BEHAVIOR").length;
  const shieldTriggers = events.filter((e) => e.event_type === "THREAT_DETECTED").length;
  const uniqueIps = new Set(events.map((e) => e.source_ip).filter(Boolean)).size;
  const arcjetEvents = events.filter((e) => e.metadata && (e.metadata as Record<string, unknown>).provider === "arcjet");
  const arcjetBlocks = arcjetEvents.filter((e) => e.action === "BLOCK").length;
  const arcjetRateLimits = arcjetEvents.filter((e) => e.event_type === "RATE_LIMITED").length;
  const arcjetBots = arcjetEvents.filter(
    (e) => e.threat_type === "BOT_BEHAVIOR" || (e.metadata && typeof (e.metadata as Record<string, unknown>).kind === "string" && ((e.metadata as Record<string, unknown>).kind as string).includes("bot")),
  ).length;
  const activeAlerts = events.filter((e) => e.severity === "HIGH" || e.severity === "CRITICAL");

  return (
    <div className="cyber-bg">
      <main className="container" style={{ paddingTop: 32, paddingBottom: 40 }}>
        <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
          <div>
            <p style={{ fontSize: 11, letterSpacing: 2, textTransform: "uppercase", color: "var(--accent)" }}>Digital Twin III</p>
            <h1 style={{ fontSize: 24, fontWeight: 700, marginTop: 4, marginBottom: 4 }}>Security Dashboard</h1>
            <p style={{ fontSize: 13, color: "var(--fg-muted)" }}>Real-time security telemetry from your live cyber lab (last 24h).</p>
          </div>
          <a href="/" className="btn-outline">{"<- Back to site"}</a>
        </header>

        {/* Overview cards */}
        <section style={{ marginBottom: 24 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(155px, 1fr))", gap: 12 }}>
            <MetricCard label="Total requests" value={events.length} desc="Events logged (24h)" />
            <MetricCard label="Allowed" value={allowed} desc="Safe or challenged" color="var(--primary)" />
            <MetricCard label="Blocked" value={blocked} desc="High-risk stopped" color="var(--destructive)" />
            <MetricCard label="Rate limits" value={rateLimited} desc="Excessive traffic" color="#facc15" />
            <MetricCard label="Bot detections" value={botDetections} desc="Automated behaviour" color="var(--accent)" />
            <MetricCard label="Shield triggers" value={shieldTriggers} desc="Threat detections" color="#a78bfa" />
            <MetricCard label="Unique IPs" value={uniqueIps} desc="Distinct sources" color="#fb923c" />
          </div>
        </section>

        {/* Arcjet */}
        <section style={{ marginBottom: 24 }}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 10 }}>Arcjet edge protection</h2>
          {arcjetEvents.length === 0 ? (
            <p style={{ fontSize: 13, color: "var(--fg-muted)" }}>No Arcjet decisions in the last 24 hours. Generate traffic to see edge firewall activity.</p>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(155px, 1fr))", gap: 12 }}>
              <MetricCard label="Arcjet blocks" value={arcjetBlocks} desc="Stopped at edge" color="#fb923c" />
              <MetricCard label="Rate limits" value={arcjetRateLimits} desc="Throttled traffic" color="#facc15" />
              <MetricCard label="Bot denials" value={arcjetBots} desc="Bots blocked" color="var(--accent)" />
            </div>
          )}
        </section>

        {/* Threat mix */}
        <section style={{ marginBottom: 24 }}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 10 }}>Threat mix (last 24 hours)</h2>
          {events.length === 0 ? (
            <p style={{ fontSize: 13, color: "var(--fg-muted)" }}>No telemetry yet. Use sandbox endpoints to generate attack traffic.</p>
          ) : (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {Object.entries(threatsByType).map(([type, count]) => (
                <div key={type} style={{ padding: "6px 14px", borderRadius: 999, border: "1px solid var(--border)", background: "var(--bg-card)", fontSize: 12 }}>
                  <span style={{ opacity: 0.75 }}>{type}</span>
                  <span style={{ marginLeft: 8, color: "var(--accent)" }}>x{count}</span>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Alerts */}
        <section style={{ marginBottom: 24 }}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 10 }}>Active alerts</h2>
          <div className="card">
            {activeAlerts.length === 0 ? (
              <p style={{ fontSize: 13, color: "var(--fg-muted)" }}>No active security alerts. Application stable under current traffic.</p>
            ) : (
              <ul style={{ listStyle: "none", padding: 0, margin: 0, fontSize: 13 }}>
                {activeAlerts.map((e) => (
                  <li key={e.id} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid var(--border)" }}>
                    <div>
                      <div><strong>{e.severity}</strong> . {e.threat_type || e.event_type}</div>
                      <div style={{ color: "var(--fg-muted)" }}>{e.endpoint} . {new Date(e.timestamp).toLocaleString()}</div>
                    </div>
                    <div style={{ fontSize: 12, color: "var(--fg-muted)" }}>{e.source_ip || "-"}</div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>

        {/* Recent activity */}
        <section style={{ marginBottom: 24 }}>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 10 }}>Recent activity</h2>
          {events.length === 0 ? (
            <p style={{ fontSize: 13, color: "var(--fg-muted)" }}>No recent events.</p>
          ) : (
            <div style={{ borderRadius: "var(--radius)", border: "1px solid var(--border)", overflow: "hidden", background: "var(--bg-card)" }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Time</th><th>Type</th><th>Severity</th><th>Action</th><th>Endpoint</th><th>IP</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id}>
                      <td>{new Date(e.timestamp).toLocaleString()}</td>
                      <td>{e.threat_type || e.event_type}</td>
                      <td>{e.severity}</td>
                      <td>{e.action}</td>
                      <td>{e.endpoint}</td>
                      <td style={{ color: "var(--fg-muted)" }}>{e.source_ip || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* Evidence */}
        <section>
          <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 10 }}>{"Evidence & reports"}</h2>
          <p style={{ fontSize: 13, color: "var(--fg-muted)", lineHeight: 1.7 }}>
            Detailed logs, risk assessments, and remediation notes are maintained in{" "}
            <a href="https://github.com/ashmin7/digital-twin-DigitalMind/blob/main/docs/security-evidence.md" target="_blank" rel="noreferrer">
              docs/security-evidence.md
            </a>.
          </p>
        </section>
      </main>
    </div>
  );
}

function MetricCard({ label, value, desc, color = "var(--accent)" }: { label: string; value: number; desc: string; color?: string }) {
  return (
    <div className="metric-card">
      <div className="label">{label}</div>
      <div className="value" style={{ color }}>{value}</div>
      <div className="desc">{desc}</div>
    </div>
  );
}
