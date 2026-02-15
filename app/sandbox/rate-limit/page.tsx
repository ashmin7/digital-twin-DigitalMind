"use client";

import { useState } from "react";

interface BurstResult {
  lastStatus: number | null;
  lastMessage: string;
  limitedCount: number;
  totalRequests: number;
}

export default function SandboxRateLimit() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BurstResult | null>(null);

  const burst = async () => {
    if (loading) return;
    setLoading(true);
    let limited = 0, total = 0, lastStatus: number | null = null, lastMessage = "";
    try {
      for (let i = 0; i < 6; i++) {
        total += 1;
        const res = await fetch("/api/sandbox/rate-limit", { method: "POST" });
        lastStatus = res.status;
        const data = await res.json().catch(() => ({}));
        lastMessage = data.message || data.error || "";
        if (!res.ok) limited += 1;
      }
    } catch {
      lastStatus = null;
      lastMessage = "Network error while sending burst.";
    } finally {
      setLoading(false);
      setResult({ lastStatus, lastMessage, limitedCount: limited, totalRequests: total });
    }
  };

  return (
    <div className="cyber-bg">
      <main className="container-sm" style={{ paddingTop: 40, paddingBottom: 40 }}>
        <a href="/sandbox" style={{ fontSize: 13, display: "inline-block", marginBottom: 16 }}>{"<- Back to sandbox"}</a>
        <h1 style={{ fontSize: 24, fontWeight: 700, marginBottom: 8 }}>Sandbox: Automated / Bot Traffic</h1>
        <p style={{ color: "var(--fg-muted)", fontSize: 14, lineHeight: 1.7, marginBottom: 24 }}>
          Sends a burst of requests to{" "}
          <code style={{ color: "var(--accent)", fontFamily: "var(--font-mono)", fontSize: 12 }}>/api/sandbox/rate-limit</code>{" "}
          to simulate scanner or bot behaviour. The backend applies rate limiting and logs events.
        </p>

        <button onClick={burst} disabled={loading} className="btn-primary">
          {loading ? "Sending burst..." : "Send burst of requests"}
        </button>

        {result && (
          <div className="card" style={{ marginTop: 24 }}>
            <p style={{ fontSize: 14 }}><strong>Total requests:</strong> {result.totalRequests}</p>
            <p style={{ fontSize: 14, marginTop: 4 }}>
              <strong>Rate-limited:</strong>{" "}
              <span style={{ color: result.limitedCount > 0 ? "var(--destructive)" : "var(--primary)" }}>{result.limitedCount}</span>
            </p>
            <p style={{ fontSize: 14, marginTop: 4 }}><strong>Last status:</strong> {result.lastStatus ?? "n/a"}</p>
            {result.lastMessage && <p style={{ fontSize: 14, color: "var(--fg-muted)", marginTop: 8 }}>{result.lastMessage}</p>}
          </div>
        )}

        <p style={{ marginTop: 24, color: "var(--fg-muted)", fontSize: 12, lineHeight: 1.7 }}>
          {"Educational note: rate limits combine with Arcjet's edge protections to slow automated recon, credential stuffing, and noisy bot traffic."}
        </p>
      </main>
    </div>
  );
}
