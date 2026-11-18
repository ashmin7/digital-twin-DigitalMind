"use client";

import { useMemo, useState } from "react";

export interface SecurityEventRow {
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

export interface DashboardStats {
  totalRequests: number;
  allowed: number;
  blocked: number;
  rateLimited: number;
  botDetections: number;
  shieldTriggers: number;
  uniqueIps: number;
  arcjetBlocks: number;
  arcjetRateLimits: number;
  arcjetBots: number;
  activeAlerts: number;
  threatsByType: Record<string, number>;
}

interface DashboardClientProps {
  events: SecurityEventRow[];
  liveConnected: boolean;
  stats: DashboardStats;
}

interface Scenario {
  code: string;
  title: string;
  description: string;
  threatType: string;
  severity: "MEDIUM" | "HIGH";
  action: "BLOCK" | "CHALLENGE";
  endpoint: string;
}

interface DemoEvent extends SecurityEventRow {
  localSimulation: true;
}

interface ActivityEvent extends SecurityEventRow {
  localSimulation: boolean;
}

const scenarios: Scenario[] = [
  {
    code: "SQL",
    title: "Injection probe",
    description: "Simulate a suspicious query pattern",
    threatType: "SQL_INJECTION",
    severity: "HIGH",
    action: "BLOCK",
    endpoint: "/sandbox/sql",
  },
  {
    code: "XSS",
    title: "Script injection",
    description: "Simulate an unsafe markup signal",
    threatType: "XSS",
    severity: "HIGH",
    action: "BLOCK",
    endpoint: "/sandbox/xss",
  },
  {
    code: "BOT",
    title: "Bot traffic burst",
    description: "Simulate an automated traffic spike",
    threatType: "BOT_BEHAVIOR",
    severity: "MEDIUM",
    action: "CHALLENGE",
    endpoint: "/sandbox/rate-limit",
  },
  {
    code: "AUTH",
    title: "Access violation",
    description: "Simulate an unauthorized access signal",
    threatType: "ACCESS_CONTROL",
    severity: "HIGH",
    action: "BLOCK",
    endpoint: "/sandbox/auth",
  },
];

const knownThreatTypes = ["SQL_INJECTION", "XSS", "BOT_BEHAVIOR", "ACCESS_CONTROL"];

function formatTime(timestamp: string) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "UTC",
  }).format(date);
}

function prettyLabel(value: string | null) {
  return (value || "UNKNOWN").replace(/_/g, " ");
}

function severityClass(severity: string) {
  const normalized = severity.toLowerCase();
  if (normalized === "critical") return "is-critical";
  if (normalized === "high") return "is-high";
  if (normalized === "medium") return "is-medium";
  return "is-low";
}

function MetricCard({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: number;
  detail: string;
  tone: "cyan" | "red" | "amber" | "green" | "violet";
}) {
  return (
    <article className={`dashboard-metric tone-${tone}`}>
      <div className="dashboard-metric-topline">
        <span className="dashboard-metric-label">{label}</span>
        <span className="dashboard-metric-mark" aria-hidden="true" />
      </div>
      <strong className="dashboard-metric-value">{value.toLocaleString("en-US")}</strong>
      <span className="dashboard-metric-detail">{detail}</span>
    </article>
  );
}

export default function DashboardClient({ events, liveConnected, stats }: DashboardClientProps) {
  const [demoEvents, setDemoEvents] = useState<DemoEvent[]>([]);
  const [announcement, setAnnouncement] = useState("");

  const activity = useMemo<ActivityEvent[]>(
    () =>
      [
        ...demoEvents.map((event) => ({ ...event, localSimulation: true })),
        ...events.map((event) => ({ ...event, localSimulation: false })),
      ]
        .sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp))
        .slice(0, 8),
    [demoEvents, events],
  );

  const threatRows = knownThreatTypes.map((type) => ({
    type,
    count: stats.threatsByType[type] || 0,
  }));
  const criticalAlerts = events.filter((event) => event.severity === "CRITICAL").length;
  const highAlerts = events.filter((event) => event.severity === "HIGH").length;

  function runScenario(scenario: Scenario) {
    const event: DemoEvent = {
      id: `demo-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      event_type: "THREAT_DETECTED",
      severity: scenario.severity,
      threat_type: scenario.threatType,
      action: scenario.action,
      endpoint: scenario.endpoint,
      source_ip: null,
      user_agent: "Local dashboard simulator",
      timestamp: new Date().toISOString(),
      metadata: { source: "local-simulator" },
      localSimulation: true,
    };

    setDemoEvents((current) => [event, ...current].slice(0, 12));
    setAnnouncement(`${scenario.title} simulated. ${scenario.action.toLowerCase()} decision added to the local event feed.`);
  }

  return (
    <div className="cyber-bg dashboard-shell">
      <main className="dashboard-container">
        <header className="dashboard-header">
          <div className="dashboard-brand">
            <span className="dashboard-brand-mark" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 3 20 6v5c0 5-3.4 8.2-8 10-4.6-1.8-8-5-8-10V6l8-3Z" />
                <path d="m8.5 12 2.2 2.2 4.8-5" />
              </svg>
            </span>
            <div>
              <p className="dashboard-kicker">ASHMIN ARYAL <span>/</span> INDEPENDENT CYBER RANGE</p>
              <h1>Security dashboard</h1>
            </div>
          </div>
          <div className="dashboard-header-actions">
            <span className={`dashboard-connection ${liveConnected ? "is-connected" : "is-disconnected"}`}>
              <span className="dashboard-connection-dot" aria-hidden="true" />
              {liveConnected ? "Live telemetry connected" : "Telemetry unavailable"}
            </span>
            <a href="/" className="dashboard-back-link">Back to lab <span aria-hidden="true">↗</span></a>
          </div>
        </header>

        <section className="dashboard-hero" aria-labelledby="dashboard-title">
          <div className="dashboard-hero-copy">
            <p className="dashboard-eyebrow"><span className="dashboard-eyebrow-line" /> DEFENSE CONSOLE <span>/</span> LAST 24 HOURS</p>
            <h2 id="dashboard-title">Observe the signal.<br /><span>Own the response.</span></h2>
            <p className="dashboard-hero-description">
              A focused view of the lab&apos;s security activity, edge decisions, and controlled training scenarios.
            </p>
            <div className="dashboard-hero-tags" aria-label="Dashboard capabilities">
              <span>EDGE MONITORING</span>
              <span>THREAT TRIAGE</span>
              <span>SAFE RANGE</span>
            </div>
          </div>
          <div className="dashboard-radar-panel">
            <div className="dashboard-radar" aria-hidden="true">
              <span className="dashboard-radar-ring ring-one" />
              <span className="dashboard-radar-ring ring-two" />
              <span className="dashboard-radar-ring ring-three" />
              <span className="dashboard-radar-cross cross-x" />
              <span className="dashboard-radar-cross cross-y" />
              <span className="dashboard-radar-sweep" />
              <span className="dashboard-radar-ping ping-one" />
              <span className="dashboard-radar-ping ping-two" />
              <span className="dashboard-radar-center" />
            </div>
            <div className="dashboard-radar-copy">
              <span className="dashboard-radar-label">LAB POSTURE</span>
              <strong>GUARDED</strong>
              <span className="dashboard-radar-note">Controlled environment<br />Signals stay in scope</span>
            </div>
            <span className="dashboard-radar-coordinate">RANGE // 001</span>
          </div>
        </section>

        <section className="dashboard-metrics" aria-label="Last 24 hour security metrics">
          <MetricCard label="Signals" value={stats.totalRequests} detail="events recorded · 24h" tone="cyan" />
          <MetricCard label="Blocked" value={stats.blocked} detail="denied by policy" tone="red" />
          <MetricCard label="Rate limited" value={stats.rateLimited} detail="traffic throttled" tone="amber" />
          <MetricCard label="Bot signals" value={stats.botDetections} detail="automated behavior" tone="violet" />
          <MetricCard label="Unique sources" value={stats.uniqueIps} detail="distinct addresses" tone="green" />
        </section>

        <div className="dashboard-section-heading">
          <div>
            <p className="dashboard-eyebrow">MONITOR / ANALYZE / REHEARSE</p>
            <h2>Operations overview</h2>
          </div>
          <span className="dashboard-window">ROLLING WINDOW <strong>24H</strong></span>
        </div>

        <div className="dashboard-grid">
          <div className="dashboard-main-column">
            <section className="dashboard-panel simulator-panel" aria-labelledby="simulator-title">
              <div className="dashboard-panel-heading">
                <div>
                  <p className="dashboard-eyebrow">CONTROLLED EXERCISES</p>
                  <h3 id="simulator-title">Scenario deck</h3>
                </div>
                <span className="dashboard-demo-badge"><span aria-hidden="true" /> LOCAL SIM</span>
              </div>
              <p className="dashboard-panel-description">
                Rehearse common threat signals and watch the response appear in the event ledger.
              </p>
              <div className="dashboard-scenario-grid">
                {scenarios.map((scenario) => (
                  <button
                    key={scenario.code}
                    type="button"
                    className="dashboard-scenario"
                    onClick={() => runScenario(scenario)}
                    aria-label={`Simulate ${scenario.title}`}
                  >
                    <span className="dashboard-scenario-code">{scenario.code}</span>
                    <span className="dashboard-scenario-copy">
                      <strong>{scenario.title}</strong>
                      <span>{scenario.description}</span>
                    </span>
                    <span className="dashboard-scenario-arrow" aria-hidden="true">↗</span>
                  </button>
                ))}
              </div>
              <div className="dashboard-simulation-notice">
                <span className="dashboard-notice-icon" aria-hidden="true">i</span>
                <p><strong>Local-only simulation.</strong> These controls add demo telemetry to this screen; they send no requests and do not touch a live target.</p>
              </div>
              <p className="sr-only" aria-live="polite" aria-atomic="true">{announcement}</p>
            </section>

            <section className="dashboard-panel event-panel" aria-labelledby="event-ledger-title">
              <div className="dashboard-panel-heading">
                <div>
                  <p className="dashboard-eyebrow">AUDIT TRAIL</p>
                  <h3 id="event-ledger-title">Latest signals</h3>
                </div>
                <span className="dashboard-event-count">{activity.length.toString().padStart(2, "0")} <span>/ 08</span></span>
              </div>
              {activity.length === 0 ? (
                <div className="dashboard-empty-state">
                  <span className="dashboard-empty-mark" aria-hidden="true">—</span>
                  <strong>No events in this window</strong>
                  <p>Run a local scenario or explore one of the isolated labs below to generate activity.</p>
                </div>
              ) : (
                <div className="dashboard-event-list" role="list" aria-label="Latest security events">
                  {activity.map((event) => (
                    <article className="dashboard-event-row" role="listitem" key={`${event.localSimulation ? "demo" : "live"}-${event.id}`}>
                      <span className={`dashboard-event-indicator ${severityClass(event.severity)}`} aria-hidden="true" />
                      <div className="dashboard-event-main">
                        <div className="dashboard-event-title-row">
                          <strong>{prettyLabel(event.threat_type || event.event_type)}</strong>
                          {event.localSimulation && <span className="dashboard-mini-badge">DEMO</span>}
                          <span className={`dashboard-severity ${severityClass(event.severity)}`}>{event.severity}</span>
                        </div>
                        <span className="dashboard-event-meta">{event.endpoint} <span>·</span> {formatTime(event.timestamp)} UTC</span>
                      </div>
                      <span className={`dashboard-verdict ${event.action.toLowerCase()}`}>{event.action}</span>
                    </article>
                  ))}
                </div>
              )}
              <div className="dashboard-event-footer">
                <span>{stats.shieldTriggers} threat detections from live telemetry</span>
                <a href="/dashboard" aria-label="Refresh dashboard data">Refresh view <span aria-hidden="true">↗</span></a>
              </div>
            </section>
          </div>

          <aside className="dashboard-side-column" aria-label="Security posture and training links">
            <section className="dashboard-panel posture-panel" aria-labelledby="posture-title">
              <div className="dashboard-panel-heading compact-heading">
                <div>
                  <p className="dashboard-eyebrow">DEFENSE STATUS</p>
                  <h3 id="posture-title">Threat posture</h3>
                </div>
                <span className={`dashboard-posture-indicator ${criticalAlerts || highAlerts ? "has-alerts" : "is-clear"}`} aria-hidden="true" />
              </div>
              <div className="dashboard-posture-status">
                <span>{criticalAlerts ? "CRITICAL" : highAlerts ? "ELEVATED" : "NOMINAL"}</span>
                <strong>{criticalAlerts + highAlerts}</strong>
                <small>high-priority alerts · 24h</small>
              </div>
              <div className="dashboard-posture-rows">
                <div><span>Edge blocks</span><strong>{stats.arcjetBlocks}</strong></div>
                <div><span>Rate controls</span><strong>{stats.arcjetRateLimits}</strong></div>
                <div><span>Bot detections</span><strong>{stats.arcjetBots}</strong></div>
                <div><span>Audit connection</span><strong className={liveConnected ? "text-green" : "text-muted"}>{liveConnected ? "CONNECTED" : "OFFLINE"}</strong></div>
              </div>
              <p className="dashboard-posture-footnote">
                {stats.allowed} safe or challenged requests recorded in the same window.
              </p>
            </section>

            <section className="dashboard-panel signal-panel" aria-labelledby="signal-mix-title">
              <div className="dashboard-panel-heading compact-heading">
                <div>
                  <p className="dashboard-eyebrow">OBSERVED VECTORS</p>
                  <h3 id="signal-mix-title">Signal mix</h3>
                </div>
                <span className="dashboard-muted-count">24H</span>
              </div>
              <div className="dashboard-signal-list">
                {threatRows.map(({ type, count }) => (
                  <div className="dashboard-signal-row" key={type}>
                    <span className="dashboard-signal-dot" aria-hidden="true" />
                    <span>{prettyLabel(type)}</span>
                    <strong>{count.toString().padStart(2, "0")}</strong>
                  </div>
                ))}
              </div>
              {stats.totalRequests === 0 && <p className="dashboard-panel-footnote">No live vector data yet. Local exercises are labeled separately.</p>}
            </section>

            <section className="dashboard-panel sandbox-panel" aria-labelledby="sandbox-title">
              <p className="dashboard-eyebrow">STAY IN SCOPE</p>
              <h3 id="sandbox-title">Isolated training labs</h3>
              <p className="dashboard-panel-description">Test within the purpose-built routes, then return here to inspect the recorded response.</p>
              <div className="dashboard-sandbox-links">
                <a href="/sandbox/sql"><span>SQL lab</span><span aria-hidden="true">↗</span></a>
                <a href="/sandbox/xss"><span>Markup lab</span><span aria-hidden="true">↗</span></a>
                <a href="/sandbox/rate-limit"><span>Traffic lab</span><span aria-hidden="true">↗</span></a>
                <a href="/sandbox/auth"><span>Access lab</span><span aria-hidden="true">↗</span></a>
              </div>
            </section>
          </aside>
        </div>

        <footer className="dashboard-footer">
          <span><span className="dashboard-footer-dot" aria-hidden="true" /> ASHMIN ARYAL&apos;S CYBER RANGE</span>
          <span>LOCAL SIMULATIONS ARE LABELED · LIVE LOGS ARE READ-ONLY</span>
        </footer>
      </main>
    </div>
  );
}
