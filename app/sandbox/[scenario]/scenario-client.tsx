"use client";

import Link from "next/link";
import { useState } from "react";
import type { LabScenario } from "../scenarios";

export default function ScenarioClient({ scenario }: { scenario: LabScenario }) {
  const [runs, setRuns] = useState(0);
  const [lastRun, setLastRun] = useState<string | null>(null);

  function runSimulation() {
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
            <p className="scenario-panel-copy">The simulator creates a sample signal and shows the expected defensive decision. It does not send attack traffic, execute payloads, or contact any target.</p>

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

            {lastRun ? (
              <div className="scenario-result" role="status" aria-live="polite">
                <div className="scenario-result-heading">
                  <span className="scenario-result-mark" aria-hidden="true">✓</span>
                  <div>
                    <p>SIMULATION COMPLETE · {lastRun} UTC</p>
                    <strong>{scenario.outcome}</strong>
                  </div>
                  <span className={`scenario-action ${scenario.action.toLowerCase()}`}>{scenario.action}</span>
                </div>
                <div className="scenario-result-details">
                  <div><span>DETECTED SIGNAL</span><strong>{scenario.signal}</strong></div>
                  <div><span>DEFENSIVE RESPONSE</span><strong>{scenario.response}</strong></div>
                  <div><span>SEVERITY</span><strong className={`scenario-severity ${scenario.severity.toLowerCase()}`}>{scenario.severity}</strong></div>
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
