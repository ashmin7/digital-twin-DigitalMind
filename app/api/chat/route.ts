import { NextRequest, NextResponse } from "next/server";
import OpenAI from "openai";
import { detectPromptInjection } from "../../../lib/security/detectors";
import { logSecurityEvent } from "../../../lib/audit-logger";
import { checkRateLimit } from "../../../lib/rate-limit";

const systemPrompt = `
You are the Digital Twin Persona of a cybersecurity professional.

GOALS:
- Explain this portfolio and the "Digital Twin III" project.
- Talk about cybersecurity topics, attack simulations, and defenses.
- Stay professional, concise, and helpful for recruiters and engineers.

SAFETY:
- Never execute real attacks; only explain them.
- If the user asks for harmful actions, explain why they are unsafe and redirect to learning.
`;
let openaiClient: OpenAI | null = null;

function getOpenAIClient(): OpenAI | null {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return null;
  if (!openaiClient) {
    openaiClient = new OpenAI({ apiKey });
  }
  return openaiClient;
}

export async function POST(request: NextRequest) {
  try {
    const ip = request.headers.get("x-forwarded-for") || "unknown";
    const userAgent = request.headers.get("user-agent") || "unknown";

    const { message, history = [] } = await request.json();

    if (!message || typeof message !== "string") {
      return NextResponse.json({ error: "Missing message" }, { status: 400 });
    }

    // Simple rate limiting per IP for this endpoint
    const rate = checkRateLimit(ip, "/api/chat");
    if (!rate.allowed) {
      await logSecurityEvent({
        eventType: "RATE_LIMITED",
        severity: "MEDIUM",
        sourceIP: ip,
        userAgent,
        endpoint: "/api/chat",
        action: "BLOCK",
        threatType: "BOT_BEHAVIOR",
        metadata: { remaining: rate.remaining, resetMs: rate.resetMs },
      });

      return NextResponse.json(
        {
          reply:
            "Too many requests in a short time. This chatbot includes rate limiting to defend against automated attacks.",
        },
        { status: 429 }
      );
    }

    // Prompt injection / harmful intent guard
    const promptCheck = detectPromptInjection(message);
    if (promptCheck.detected) {
      await logSecurityEvent({
        eventType: "THREAT_BLOCKED",
        severity: "HIGH",
        sourceIP: ip,
        userAgent,
        endpoint: "/api/chat",
        payload: message,
        threatType: "PROMPT_INJECTION",
        action: "BLOCK",
        metadata: { patterns: promptCheck.patterns },
      });

      return NextResponse.json({
        reply:
          "This assistant detected a prompt-injection style request. I can explain how these attacks work and how to defend against them, but I won't follow instructions that try to override my safety rules.",
      });
    }

    const client = getOpenAIClient();
    if (!client) {
      // Graceful fallback when chat is not configured
      return NextResponse.json({
        reply:
          "The AI backend is not configured on this deployment yet. Please set OPENAI_API_KEY to enable the Digital Twin chatbot.",
      });
    }

    const messages = [
      { role: "system" as const, content: systemPrompt },
      ...history.map((m: any) => ({ role: m.role, content: m.content })),
      { role: "user" as const, content: message },
    ];

    const completion = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages,
      temperature: 0.7,
      max_tokens: 700,
    });

    const reply =
      completion.choices[0]?.message?.content ??
      "I had trouble generating a response. Please try again.";

    await logSecurityEvent({
      eventType: "THREAT_DETECTED",
      severity: "LOW",
      sourceIP: ip,
      userAgent,
      endpoint: "/api/chat",
      action: "ALLOW",
      metadata: { length: message.length },
    });

    return NextResponse.json({ reply });
  } catch (error) {
    console.error("/api/chat error", error);
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}
