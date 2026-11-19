"use client";

import Link from "next/link";
import { useState } from "react";
import type { LabScenario } from "../scenarios";

type SimulationResult = {
  signal: string;
  response: string;
  outcome: string;
  severity: "LOW" | "MEDIUM" | "HIGH";
  action: "ALLOW" | "BLOCK" | "CHALLENGE";
  inputSummary: string;
  preview?: string;
};

export default function ScenarioClient({ scenario }: { scenario: LabScenario }) {
  const [runs, setRuns] = useState(0);
  const [lastRun, setLastRun] = useState<string | null>(null);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [sampleInput, setSampleInput] = useState("");
  const [requestCount, setRequestCount] = useState("12");
  const [requesterRole, setRequesterRole] = useState("visitor");
  const [requestedResource, setRequestedResource] = useState("admin-console");

  function runSimulation() {
    let nextResult: SimulationResult;

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

    setResult(nextResult);
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
              <span>LOCAL SIMULATION</span>
              <span>NO NETWORK TRAFFIC</span>
              <span>CONTROLLED SCOPE</span>
            </div>
          </div>
          <div className="scenario-posture" aria-label="Simulation status">
            <span className="scenario-posture-label">RANGE STATUS</span>
            <strong><span aria-hidden="true" /> ISOLATED</strong>
            <small>Nothing is sent to a real service.</small>
          </div>
        </section>

        <div className="scenario-layout">
          <section className="scenario-panel scenario-run-panel" aria-labelledby="run-title">
            <div className="scenario-panel-heading">
              <div>
                <p className="scenario-eyebrow">DEFENSIVE REHEARSAL</p>
                <h2 id="run-title">Run the scenario</h2>
              </div>
              <span className="scenario-run-count">RUNS <strong>{runs.toString().padStart(2, "0")}</strong></span>
            </div>
            <p className="scenario-panel-copy">Try your own sample below. Analysis happens in this browser only; no requests are sent, no scripts or queries are executed, and no live target is contacted.</p>

            {scenario.id === "SQL-01" && (
              <label className="scenario-field">
                <span>Query input to inspect</span>
                <input className="scenario-input" type="text" maxLength={160} value={sampleInput} onChange={(event) => setSampleInput(event.target.value)} placeholder="Type or paste a sample value" />
                <small>Illustrative signal check only; this is not a complete SQL parser.</small>
              </label>
            )}
            {scenario.id === "XSS-02" && (
              <label className="scenario-field">
                <span>Text to inspect and render safely</span>
                <textarea className="scenario-input scenario-textarea" maxLength={240} value={sampleInput} onChange={(event) => setSampleInput(event.target.value)} placeholder="Type or paste markup-like text" rows={3} />
                <small>The result is rendered as text and is never interpreted as HTML.</small>
              </label>
            )}
            {scenario.id === "RATE-03" && (
              <label className="scenario-field">
                <span>Number of requests to model</span>
                <input className="scenario-input scenario-number-input" type="number" min={0} max={50} value={requestCount} onChange={(event) => setRequestCount(event.target.value)} />
                <small>Models at most 50 requests; it does not generate network traffic.</small>
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
              {runs > 0 ? "Run simulation again" : "Run safe simulation"}
              <span aria-hidden="true">→</span>
            </button>

            {lastRun && result ? (
              <div className="scenario-result" role="status" aria-live="polite">
                <div className="scenario-result-heading">
                  <span className="scenario-result-mark" aria-hidden="true">✓</span>
                  <div>
                    <p>SIMULATION COMPLETE · {lastRun} UTC</p>
                    <strong>{result.outcome}</strong>
                  </div>
                  <span className={`scenario-action ${result.action.toLowerCase()}`}>{result.action}</span>
                </div>
                <div className="scenario-result-details">
                  <div><span>OBSERVED</span><strong>{result.signal}</strong></div>
                  <div><span>POLICY RESPONSE</span><strong>{result.response}</strong></div>
                  <div><span>SEVERITY</span><strong className={`scenario-severity ${result.severity.toLowerCase()}`}>{result.severity}</strong></div>
                  <div><span>LOCAL CHECK</span><strong>{result.inputSummary}</strong></div>
                  {result.preview !== undefined && <div><span>SAFE TEXT PREVIEW</span><code className="scenario-safe-preview">{result.preview}</code></div>}
                </div>
              </div>
            ) : (
              <p className="scenario-idle-note">Ready when you are. Results are generated in this browser session only.</p>
            )}
          </section>

          <aside className="scenario-side-column" aria-label="Scenario context">
            <section className="scenario-panel">
              <p className="scenario-eyebrow">POLICY FLOW</p>
              <h2>What this demonstrates</h2>
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
