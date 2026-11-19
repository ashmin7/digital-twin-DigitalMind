"use client";

import Link from "next/link";
import { useMemo } from "react";
import { useRangeRuns } from "../range-run-context";

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
  endpoint: string;
}

interface ActivityEvent extends SecurityEventRow {
  localSimulation: boolean;
}

const scenarios: Scenario[] = [
  { code: "SQL", title: "Query boundary", description: "Open the injection-defense replay", endpoint: "/sandbox/sql" },
  { code: "XSS", title: "Output encoding", description: "Open the browser-rendering replay", endpoint: "/sandbox/xss" },
  { code: "RATE", title: "Traffic controls", description: "Open the rate-control replay", endpoint: "/sandbox/rate-limit" },
  { code: "AUTH", title: "Access policy", description: "Open the authorization replay", endpoint: "/sandbox/auth" },
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
  const { runs: rangeRuns } = useRangeRuns();
  const latestRun = rangeRuns[0] ?? null;

  const rangeEvents = useMemo<ActivityEvent[]>(
    () => rangeRuns.map((run) => ({
      id: run.id,
      event_type: "RANGE_SIMULATION_COMPLETE",
      severity: run.severity,
      threat_type: run.threatType,
      action: run.action,
      endpoint: run.path,
      source_ip: run.sourceIp,
      user_agent: "Contained client-side emulator",
      timestamp: run.timestamp,
      metadata: {
        source: "scenario-lab",
        outcome: run.outcome,
        statusCode: run.statusCode,
        transactionId: run.transactionId,
      },
      localSimulation: true,
    })),
    [rangeRuns],
  );

  const activity = useMemo<ActivityEvent[]>(
    () => [...rangeEvents, ...events.map((event) => ({ ...event, localSimulation: false }))]
      .sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp))
      .slice(0, 8),
    [rangeEvents, events],
  );

  const threatRows = knownThreatTypes.map((type) => ({
    type,
    count: (stats.threatsByType[type] || 0) + rangeRuns.filter((run) => run.threatType === type).length,
  }));
  const criticalAlerts = events.filter((event) => event.severity === "CRITICAL").length;
  const highAlerts = events.filter((event) => event.severity === "HIGH").length
    + rangeRuns.filter((run) => run.severity === "HIGH").length;

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
            <span className={`dashboard-connection ${liveConnected ? "is-connected" : rangeRuns.length ? "is-local" : "is-disconnected"}`}>
              <span className="dashboard-connection-dot" aria-hidden="true" />
              {liveConnected ? "Live telemetry connected" : rangeRuns.length ? "Local range session active" : "Live telemetry offline"}
            </span>
            <Link href="/" className="dashboard-back-link">Back to lab <span aria-hidden="true">↗</span></Link>
          </div>
        </header>

        <section className="dashboard-hero" aria-labelledby="dashboard-title">
          <div className="dashboard-hero-copy">
            <p className="dashboard-eyebrow"><span className="dashboard-eyebrow-line" /> DEFENSE CONSOLE <span>/</span> LIVE 24H + SESSION</p>
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

        <section className="dashboard-metrics" aria-label="Live security metrics and current session activity">
          <MetricCard label="Live signals" value={stats.totalRequests} detail="telemetry · 24h" tone="cyan" />
          <MetricCard label="Blocked" value={stats.blocked} detail="denied by live policy" tone="red" />
          <MetricCard label="Rate limited" value={stats.rateLimited} detail="live traffic throttled" tone="amber" />
          <MetricCard label="Bot signals" value={stats.botDetections} detail="live automated behavior" tone="violet" />
          <MetricCard label="Unique sources" value={stats.uniqueIps} detail="live addresses · 24h" tone="green" />
          <MetricCard label="Range runs" value={rangeRuns.length} detail="this browser session" tone="cyan" />
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
            <section className="dashboard-panel dashboard-latest-run" aria-labelledby="latest-run-title">
              <div className="dashboard-panel-heading">
                <div>
                  <p className="dashboard-eyebrow">SESSION TRACE</p>
                  <h3 id="latest-run-title">Latest range result</h3>
                </div>
                {latestRun && <span className="dashboard-run-id">{latestRun.transactionId}</span>}
              </div>
              {latestRun ? (
                <>
                  <div className="dashboard-latest-run-summary">
                    <div><span>SCENARIO</span><strong>{latestRun.title}</strong></div>
                    <div><span>OUTCOME</span><strong>{latestRun.outcome}</strong></div>
                    <div><span>HTTP</span><strong className={`dashboard-http-result ${latestRun.statusCode >= 400 ? "is-blocked" : "is-success"}`}>{latestRun.statusCode}</strong></div>
                    <div><span>DECISION</span><strong className={`dashboard-verdict ${latestRun.action.toLowerCase()}`}>{latestRun.action}</strong></div>
                  </div>
                  <p className="dashboard-latest-run-response">{latestRun.response}</p>
                  <ol className="dashboard-latest-trace">
                    {latestRun.trace.map((entry, index) => (
                      <li key={`${latestRun.id}-${index}`}><span>{String(index + 1).padStart(2, "0")}</span><code>{entry}</code></li>
                    ))}
                  </ol>
                </>
              ) : (
                <div className="dashboard-empty-run">
                  <strong>No contained runs in this session</strong>
                  <p>Open a lab, execute a contained run, and its outcome and trace will appear here.</p>
                </div>
              )}
            </section>

            <section className="dashboard-panel simulator-panel" aria-labelledby="simulator-title">
              <div className="dashboard-panel-heading">
                <div>
                  <p className="dashboard-eyebrow">CONTROLLED EXERCISES</p>
                  <h3 id="simulator-title">Scenario deck</h3>
                </div>
                <span className="dashboard-demo-badge"><span aria-hidden="true" /> LOCAL SIM</span>
              </div>
              <p className="dashboard-panel-description">
                Open a contained scenario, configure its test signal, and return here to review the generated transaction trace.
              </p>
              <div className="dashboard-scenario-grid">
                {scenarios.map((scenario) => (
                  <Link
                    key={scenario.code}
                    href={scenario.endpoint}
                    className="dashboard-scenario"
                    aria-label={`Open ${scenario.title} lab`}
                  >
                    <span className="dashboard-scenario-code">{scenario.code}</span>
                    <span className="dashboard-scenario-copy">
                      <strong>{scenario.title}</strong>
                      <span>{scenario.description}</span>
                    </span>
                    <span className="dashboard-scenario-arrow" aria-hidden="true">↗</span>
                  </Link>
                ))}
              </div>
              <div className="dashboard-simulation-notice">
                <span className="dashboard-notice-icon" aria-hidden="true">i</span>
                <p><strong>Contained by design.</strong> Each lab runs a local policy model; results return to this dashboard during the current browser session.</p>
              </div>
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
                          {event.localSimulation && <span className="dashboard-mini-badge">RANGE</span>}
                          <span className={`dashboard-severity ${severityClass(event.severity)}`}>{event.severity}</span>
                        </div>
                        <span className="dashboard-event-meta">{event.endpoint} <span>·</span> {formatTime(event.timestamp)} UTC</span>
                        {event.localSimulation && <span className="dashboard-event-result">{String(event.metadata?.outcome || "RANGE RUN")} · HTTP {String(event.metadata?.statusCode ?? "—")}</span>}
                      </div>
                      <span className={`dashboard-verdict ${event.action.toLowerCase()}`}>{event.action}</span>
                    </article>
                  ))}
                </div>
              )}
              <div className="dashboard-event-footer">
                <span>{stats.shieldTriggers} threat detections from live telemetry</span>
                <span>{rangeRuns.length} contained run{rangeRuns.length === 1 ? "" : "s"} in this session</span>
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
                <small>high-priority · live + session</small>
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
                <span className="dashboard-muted-count">LIVE + SESSION</span>
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
                <Link href="/sandbox/sql"><span>SQL lab</span><span aria-hidden="true">↗</span></Link>
                <Link href="/sandbox/xss"><span>Markup lab</span><span aria-hidden="true">↗</span></Link>
                <Link href="/sandbox/rate-limit"><span>Traffic lab</span><span aria-hidden="true">↗</span></Link>
                <Link href="/sandbox/auth"><span>Access lab</span><span aria-hidden="true">↗</span></Link>
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
