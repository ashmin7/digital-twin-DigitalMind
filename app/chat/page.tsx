"use client";

import { useState, type KeyboardEvent } from "react";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export default function ChatPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  const sendMessage = async () => {
    const trimmed = input.trim();
    if (!trimmed || loading) return;

    const nextMessages = [...messages, { role: "user" as const, content: trimmed }];
    setMessages(nextMessages);
    setInput("");
    setLoading(true);

    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: trimmed, history: nextMessages }),
      });
      const data = await res.json();
      const reply = data.reply || data.message || "No response received.";
      setMessages((prev) => [...prev, { role: "assistant", content: reply }]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: "Error connecting to backend. Please check OPENAI_API_KEY is configured." },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="cyber-bg" style={{ display: "flex", justifyContent: "center", padding: "40px 16px" }}>
      <div
        style={{
          width: "100%",
          maxWidth: 720,
          borderRadius: 16,
          border: "1px solid rgba(30,41,59,0.5)",
          background: "radial-gradient(circle at top, rgba(56,189,248,0.15), transparent 55%), var(--bg-card)",
          display: "flex",
          flexDirection: "column",
          padding: 20,
        }}
      >
        <header style={{ marginBottom: 14 }}>
          <h1 style={{ fontSize: 20, fontWeight: 700, marginBottom: 6 }}>
            {"Digital Twin Chatbot (Prompt Injection Lab)"}
          </h1>
          <p style={{ fontSize: 13, color: "var(--fg-muted)", lineHeight: 1.6 }}>
            This assistant is tuned for cybersecurity topics and is protected against prompt-injection
            attempts. Detected attacks are blocked and logged as{" "}
            <code style={{ color: "var(--accent)", fontFamily: "var(--font-mono)", fontSize: 12 }}>PROMPT_INJECTION</code>{" "}
            events in the security dashboard.
          </p>
        </header>

        <div
          style={{
            flex: 1,
            minHeight: 280,
            maxHeight: 420,
            overflowY: "auto",
            padding: 10,
            borderRadius: 12,
            background: "rgba(11,18,37,0.8)",
            marginBottom: 14,
          }}
        >
          {messages.length === 0 && (
            <p style={{ fontSize: 13, color: "var(--fg-muted)" }}>
              {'Start with something like: "What does Digital Twin III demonstrate?"'}
            </p>
          )}
          {messages.map((m, idx) => (
            <div key={idx} style={{ marginBottom: 8, display: "flex", justifyContent: m.role === "user" ? "flex-end" : "flex-start" }}>
              <div
                style={{
                  maxWidth: "80%",
                  padding: "8px 14px",
                  borderRadius: 10,
                  fontSize: 14,
                  whiteSpace: "pre-wrap",
                  background: m.role === "user" ? "var(--primary)" : "var(--border)",
                  color: m.role === "user" ? "var(--bg)" : "var(--fg)",
                }}
              >
                {m.content}
              </div>
            </div>
          ))}
        </div>

        <div>
          <textarea
            rows={3}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a question about your digital twin, security setup, or attack simulations..."
            className="input"
            style={{ resize: "none", marginBottom: 8, fontFamily: "var(--font-sans)" }}
          />
          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <button onClick={sendMessage} disabled={loading} className="btn-primary">
              {loading ? "Sending..." : "Send"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
