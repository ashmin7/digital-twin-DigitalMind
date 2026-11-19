"use client";

import Link from "next/link";
import { useState } from "react";
import { useRangeRuns } from "../../range-run-context";
import type { LabScenario } from "../scenarios";

type SimulationResult = {
  signal: string;
  response: string;
  outcome: string;
  severity: "LOW" | "MEDIUM" | "HIGH";
  action: "ALLOW" | "BLOCK" | "CHALLENGE";
  inputSummary: string;
  preview?: string;
  method: "GET" | "POST";
  path: string;
  sourceIp: string;
  destination: string;
  statusCode: number;
  transactionId: string;
  trace: string[];
};

type SimulationOutcome = Pick<SimulationResult, "signal" | "response" | "outcome" | "severity" | "action" | "inputSummary" | "preview">;

const scenarioPaths: Record<string, string> = {
  "SQL-01": "/range/sql/inspect",
  "XSS-02": "/range/xss/render",
  "RATE-03": "/range/traffic/model",
  "AUTH-04": "/range/access/check",
};

export default function ScenarioClient({ scenario }: { scenario: LabScenario }) {
  const { addRun } = useRangeRuns();
  const [runs, setRuns] = useState(0);
  const [lastRun, setLastRun] = useState<string | null>(null);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [sampleInput, setSampleInput] = useState("");
  const [requestCount, setRequestCount] = useState("12");
  const [requesterRole, setRequesterRole] = useState("visitor");
  const [requestedResource, setRequestedResource] = useState("admin-console");

  function runSimulation() {
    let nextResult: SimulationOutcome;

    if (scenario.id === "SQL-01") {
      const hasQueryMarkers = /(?:['"`=;]|--|\/\*|\*\/|\b(?:select|union|insert|update|delete|drop)\b)/i.test(sampleInput);
      nextResult = {
        signal: hasQueryMarkers ? "Query-like syntax markers found in sample" : "No query-like markers found in sample",
        response: "Parameterized-query handling keeps the sample as a value; nothing is executed.",
        outcome: hasQueryMarkers ? "INPUT KEPT AS DATA" : "SAFE SAMPLE",
        severity: hasQueryMarkers ? "MEDIUM" : "LOW",
        action: "ALLOW",
        inputSummary: `${sampleInput.length} characters inspected in this browser`,
        preview: sampleInput || "No sample entered",
      };
    } else if (scenario.id === "XSS-02") {
      const hasMarkupDelimiters = /[<>]/.test(sampleInput);
      nextResult = {
        signal: hasMarkupDelimiters ? "Markup delimiters found in sample" : "Plain-text sample provided",
        response: "React renders the sample as text; no HTML parsing or script execution occurs.",
        outcome: hasMarkupDelimiters ? "DISPLAY STAYS INERT" : "PLAIN TEXT",
        severity: hasMarkupDelimiters ? "MEDIUM" : "LOW",
        action: "ALLOW",
        inputSummary: "Output is displayed as an escaped text node",
        preview: sampleInput || "No sample entered",
      };
    } else if (scenario.id === "RATE-03") {
      const modeledRequests = Math.max(0, Math.min(50, Number.parseInt(requestCount, 10) || 0));
      const exceededLimit = modeledRequests > 5;
      nextResult = {
        signal: `${modeledRequests} requests modeled against a sample limit of 5`,
        response: exceededLimit ? "Requests above the sample threshold receive a challenge." : "The modeled request count stays within the sample threshold.",
        outcome: exceededLimit ? "BURST CHALLENGED" : "WITHIN LIMIT",
        severity: exceededLimit ? "MEDIUM" : "LOW",
        action: exceededLimit ? "CHALLENGE" : "ALLOW",
        inputSummary: "Count-only model; no requests were generated",
      };
    } else {
      const allowed = requestedResource === "public-page"
        || (requestedResource === "profile" && requesterRole !== "visitor")
        || (requestedResource === "admin-console" && requesterRole === "admin");
      nextResult = {
        signal: `${requesterRole} role requested ${requestedResource}`,
        response: allowed ? "The sample role policy grants this request." : "The sample role policy denies access before data is returned.",
        outcome: allowed ? "ACCESS ALLOWED" : "ACCESS DENIED",
        severity: allowed ? "LOW" : "HIGH",
        action: allowed ? "ALLOW" : "BLOCK",
        inputSummary: "Role decision evaluated locally; no account or protected data was used",
      };
    }

    const method = scenario.id === "AUTH-04" ? "GET" : "POST";
    const path = scenarioPaths[scenario.id] ?? "/range/session/replay";
    const statusCode = scenario.id === "RATE-03"
      ? (nextResult.action === "CHALLENGE" ? 429 : 204)
      : scenario.id === "AUTH-04" && nextResult.action === "BLOCK" ? 403 : 200;
    const transactionId = `SIM-${Date.now().toString(36).toUpperCase()}`;
    const result: SimulationResult = {
      ...nextResult,
      method,
      path,
      sourceIp: "192.0.2.44",
      destination: "range.local",
      statusCode,
      transactionId,
      trace: [
        "00.000  RANGE     isolated HTTP emulator ready",
        `00.004  INGRESS   ${method} ${path} · synthetic transaction`,
        `00.012  SIGNAL    ${nextResult.signal}`,
        `00.018  CONTROL   ${nextResult.response}`,
        `00.026  EGRESS    HTTP ${statusCode} · ${nextResult.outcome}`,
      ],
    };

    setResult(result);
    addRun({
      scenarioId: scenario.id,
      title: scenario.title,
      threatType: scenario.id === "SQL-01" ? "SQL_INJECTION" : scenario.id === "XSS-02" ? "XSS" : scenario.id === "RATE-03" ? "BOT_BEHAVIOR" : "ACCESS_CONTROL",
      timestamp: new Date().toISOString(),
      method: result.method,
      path: result.path,
      sourceIp: result.sourceIp,
      destination: result.destination,
      statusCode: result.statusCode,
      transactionId: result.transactionId,
      signal: result.signal,
      response: result.response,
      outcome: result.outcome,
      severity: result.severity,
      action: result.action,
      inputSummary: result.inputSummary,
      trace: result.trace,
    });
    setRuns((current) => current + 1);
    setLastRun(new Intl.DateTimeFormat("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      timeZone: "UTC",
    }).format(new Date()));
  }

  return (
    <div className="cyber-bg scenario-shell">
      <main className="scenario-container">
        <header className="scenario-header">
          <Link href="/" className="scenario-brand">
            <span className="scenario-brand-dot" aria-hidden="true" />
            Digital Twin III <span>/</span> Safe range
          </Link>
          <nav aria-label="Lab navigation" className="scenario-nav">
            <Link href="/dashboard">Security dashboard</Link>
            <Link href="/#sandbox">All scenarios</Link>
          </nav>
        </header>

        <section className="scenario-hero" aria-labelledby="scenario-title">
          <div>
            <p className="scenario-eyebrow"><span>{scenario.id}</span> / {scenario.category}</p>
            <h1 id="scenario-title">{scenario.title}</h1>
            <p className="scenario-description">{scenario.description}</p>
            <div className="scenario-tags" aria-label="Simulation scope">
              <span>ISOLATED RANGE</span>
              <span>SYNTHETIC HTTP</span>
              <span>NO PACKETS SENT</span>
            </div>
          </div>
          <div className="scenario-posture" aria-label="Simulation status">
            <span className="scenario-posture-label">RANGE STATUS</span>
            <strong><span aria-hidden="true" /> ISOLATED</strong>
            <small>Nothing is sent to a real service.</small>
          </div>
        </section>

        <section className="scenario-network-strip" aria-label="Isolated simulated network">
          <div><span>SIMULATED SOURCE</span><strong>192.0.2.44 <small>TEST-NET</small></strong></div>
          <span className="scenario-network-arrow" aria-hidden="true">→</span>
          <div><span>VIRTUAL TARGET</span><strong>range.local <small>ISOLATED</small></strong></div>
          <div className="scenario-network-engine"><span>ENGINE</span><strong>CLIENT-SIDE HTTP EMULATOR</strong></div>
        </section>

        <div className="scenario-layout">
          <section className="scenario-panel scenario-run-panel" aria-labelledby="run-title">
            <div className="scenario-panel-heading">
              <div>
                <p className="scenario-eyebrow">CONTAINED RANGE REPLAY</p>
                <h2 id="run-title">Build the transaction</h2>
              </div>
              <span className="scenario-run-count">RUNS <strong>{runs.toString().padStart(2, "0")}</strong></span>
            </div>
            <p className="scenario-panel-copy">Configure the test signal, then replay it through a local policy model. The console creates a synthetic request trace; it sends no packets and executes no attack code.</p>

            {scenario.id === "SQL-01" && (
              <label className="scenario-field">
                <span>Query-layer input</span>
                <input className="scenario-input" type="text" maxLength={160} value={sampleInput} onChange={(event) => setSampleInput(event.target.value)} placeholder="Enter text for the local inspection path" />
                <small>Detection is illustrative; the input is never executed as a query.</small>
              </label>
            )}
            {scenario.id === "XSS-02" && (
              <label className="scenario-field">
                <span>Untrusted content for the render path</span>
                <textarea className="scenario-input scenario-textarea" maxLength={240} value={sampleInput} onChange={(event) => setSampleInput(event.target.value)} placeholder="Enter content for the local rendering check" rows={3} />
                <small>Content is rendered as text only; no HTML or script is interpreted.</small>
              </label>
            )}
            {scenario.id === "RATE-03" && (
              <label className="scenario-field">
                <span>Synthetic request volume</span>
                <input className="scenario-input scenario-number-input" type="number" min={0} max={50} value={requestCount} onChange={(event) => setRequestCount(event.target.value)} />
                <small>Models up to 50 requests in memory; no traffic is generated.</small>
              </label>
            )}
            {scenario.id === "AUTH-04" && (
              <div className="scenario-access-fields">
                <label className="scenario-field">
                  <span>Requesting role</span>
                  <select className="scenario-input" value={requesterRole} onChange={(event) => setRequesterRole(event.target.value)}>
                    <option value="visitor">Visitor</option>
                    <option value="member">Member</option>
                    <option value="admin">Admin</option>
                  </select>
                </label>
                <label className="scenario-field">
                  <span>Requested resource</span>
                  <select className="scenario-input" value={requestedResource} onChange={(event) => setRequestedResource(event.target.value)}>
                    <option value="public-page">Public page</option>
                    <option value="profile">Member profile</option>
                    <option value="admin-console">Admin console</option>
                  </select>
                </label>
                <p className="scenario-field-help">Sample role rules only; no real identity or protected record is accessed.</p>
              </div>
            )}

            <ol className="scenario-steps">
              {scenario.steps.map((step, index) => (
                <li key={step}>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <strong>{step}</strong>
                </li>
              ))}
            </ol>

            <button type="button" className="scenario-run-button" onClick={runSimulation}>
              {runs > 0 ? "Replay contained transaction" : "Execute contained run"}
              <span aria-hidden="true">→</span>
            </button>

            {lastRun && result ? (
              <div className="scenario-result" role="status" aria-live="polite">
                <div className="scenario-result-heading">
                  <span className="scenario-result-mark" aria-hidden="true">✓</span>
                  <div>
                  <p>RANGE RUN COMPLETE · {lastRun} UTC</p>
                  <strong>{result.outcome}</strong>
                </div>
                <strong className={`scenario-http-status ${result.statusCode === 429 ? "limited" : result.statusCode >= 400 ? "blocked" : "success"}`}>HTTP {result.statusCode}</strong>
                <span className={`scenario-action ${result.action.toLowerCase()}`}>{result.action}</span>
              </div>
              <div className="scenario-result-details">
                <div><span>OBSERVED</span><strong>{result.signal}</strong></div>
                <div><span>POLICY RESPONSE</span><strong>{result.response}</strong></div>
                <div><span>SEVERITY</span><strong className={`scenario-severity ${result.severity.toLowerCase()}`}>{result.severity}</strong></div>
                <div><span>LOCAL CHECK</span><strong>{result.inputSummary}</strong></div>
                {result.preview !== undefined && <div><span>SAFE TEXT PREVIEW</span><code className="scenario-safe-preview">{result.preview}</code></div>}
              </div>
              <section className="scenario-transaction" aria-label="Synthetic HTTP transaction trace">
                <div className="scenario-transaction-heading">
                  <span>ISOLATED TRANSACTION TRACE</span>
                  <code>{result.transactionId}</code>
                </div>
                <div className="scenario-transaction-meta">
                  <div><span>CLIENT</span><code>{result.sourceIp}</code></div>
                  <div><span>VIRTUAL HOST</span><code>{result.destination}</code></div>
                  <div><span>REQUEST</span><code>{result.method} {result.path}</code></div>
                </div>
                <ol className="scenario-trace-list">
                  {result.trace.map((entry, index) => (
                    <li key={`${result.transactionId}-${index}`}>
                      <span>{String(index + 1).padStart(2, "0")}</span>
                      <code>{entry}</code>
                    </li>
                  ))}
                </ol>
                <p className="scenario-trace-note">Synthetic telemetry only · no packet was sent to this virtual host.</p>
              </section>
            </div>

            ) : (
              <p className="scenario-idle-note">Ready when you are. Results are generated in this browser session only.</p>
            )}
          </section>

          <aside className="scenario-side-column" aria-label="Scenario context">
            <section className="scenario-panel">
              <p className="scenario-eyebrow">DEFENSE PIPELINE</p>
              <h2>Controls under test</h2>
              <div className="scenario-flow">
                <div><span className="scenario-flow-index">01</span><p><strong>Signal</strong><span>{scenario.signal}</span></p></div>
                <div><span className="scenario-flow-index">02</span><p><strong>Control</strong><span>{scenario.response}</span></p></div>
                <div><span className="scenario-flow-index">03</span><p><strong>Decision</strong><span>{scenario.outcome}</span></p></div>
              </div>
            </section>
            <section className="scenario-scope-card">
              <span className="scenario-scope-icon" aria-hidden="true">i</span>
              <div>
                <strong>Safe by design</strong>
                <p>This is a visual training simulation, not a live exploit or penetration test. No requests leave this page.</p>
              </div>
            </section>
          </aside>
        </div>

        <footer className="scenario-footer">
          <span><span className="scenario-footer-dot" aria-hidden="true" /> ASHMIN ARYAL&apos;S CYBER RANGE</span>
          <Link href="/dashboard">Return to security dashboard <span aria-hidden="true">↗</span></Link>
        </footer>
      </main>
    </div>
  );
}
