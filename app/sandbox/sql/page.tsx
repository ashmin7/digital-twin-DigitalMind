"use client";

import { useState, type FormEvent } from "react";

interface Result {
  isThreat: boolean;
  patterns: string[];
  action: string;
  severity: string;
  message: string;
}

export default function SandboxSQL() {
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);

  const onSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const data = new FormData(e.currentTarget);
    const input = String(data.get("payload") || "").trim();
    if (!input || loading) return;
    setLoading(true);
    setResult(null);
    try {
      const res = await fetch("/api/sandbox/sql", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input }),
      });
      const json = await res.json();
      if (!res.ok) {
        setResult({ isThreat: false, patterns: [], action: "ERROR", severity: "LOW", message: json.error || "Unexpected error." });
      } else {
        setResult({ isThreat: !!json.isThreat, patterns: json.patterns || [], action: json.action, severity: json.severity, message: json.message });
      }
    } catch {
      setResult({ isThreat: false, patterns: [], action: "ERROR", severity: "LOW", message: "Network error." });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="cyber-bg">
      <main className="container-sm" style={{ paddingTop: 40, paddingBottom: 40 }}>
        <a href="/sandbox" style={{ fontSize: 13, display: "inline-block", marginBottom: 16 }}>{"<- Back to sandbox"}</a>
        <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Sandbox: SQL Injection</h1>
        <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 24 }}>
          Try common SQL payloads. The backend runs detection, logs events, and shows whether the input would be blocked.
        </p>

        <form onSubmit={onSubmit} style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <label style={{ fontSize: 14 }}>
            Test input
            <input name="payload" type="text" placeholder="e.g., ' OR 1=1 --" className="input" style={{ marginTop: 6 }} />
          </label>
          <button type="submit" disabled={loading} className="btn-primary" style={{ alignSelf: "flex-start" }}>
            {loading ? "Analysing..." : "Submit"}
          </button>
        </form>

        <p style={{ marginTop: 24, color: "var(--fg-muted)", fontSize: 12, lineHeight: 1.7 }}>
          Educational note: In production, parameterized queries and strict input validation prevent SQL injection.
          This demo shows detection + logging powering your security dashboard.
        </p>

        {result && (
          <div className={result.isThreat ? "result-threat" : "result-safe"} style={{ marginTop: 24 }}>
            <p style={{ fontSize: 14, fontWeight: 600, margin: 0 }}>
              {result.isThreat ? "Potential SQL injection detected" : "No obvious SQL injection detected"}
            </p>
            <p style={{ fontSize: 14, color: "var(--fg-muted)", marginTop: 6 }}>{result.message}</p>
            {result.patterns.length > 0 && (
              <p style={{ fontSize: 12, color: "var(--fg-muted)", marginTop: 4 }}>Matched patterns: {result.patterns.join(", ")}</p>
            )}
            <p style={{ fontSize: 12, color: "var(--fg-muted)", marginTop: 4 }}>
              Action: <strong style={{ color: "var(--fg)" }}>{result.action}</strong> | Severity: <strong style={{ color: "var(--fg)" }}>{result.severity}</strong>
            </p>
          </div>
        )}
      </main>
    </div>
  );
}
