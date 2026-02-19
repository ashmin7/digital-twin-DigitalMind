import { NextRequest, NextResponse } from "next/server";
import { aj } from "../../../lib/arcjet";
import { logSecurityEvent } from "../../../lib/audit-logger";

/**
 * Arcjet Test Endpoint
 * 
 * This endpoint demonstrates Arcjet WAF protection capabilities.
 * It can be used to test rate limiting, bot detection, and shield protection.
 * 
 * Usage:
 * - GET /api/arcjet - Returns current protection status
 * - POST /api/arcjet - Tests protection with custom payload
 */

export async function GET(request: NextRequest) {
  const ip = request.headers.get("x-forwarded-for") || "127.0.0.1";
  const userAgent = request.headers.get("user-agent") || "unknown";

  // If Arcjet is not configured, return graceful fallback
  if (!aj) {
    return NextResponse.json({
      status: "disabled",
      message: "Arcjet is not configured. Set ARCJET_KEY to enable WAF protection.",
      protection: {
        shield: false,
        botDetection: false,
        rateLimiting: false,
      },
    });
  }

  try {
    // Run Arcjet protection check
    const decision = await aj.protect(request, { requested: 1 });

    const response = {
      status: decision.isDenied() ? "blocked" : "allowed",
      decision: {
        conclusion: decision.conclusion,
        reason: decision.reason,
        ruleResults: decision.results.map((r) => ({
          ruleId: r.ruleId,
          state: r.state,
          conclusion: r.conclusion,
        })),
      },
      protection: {
        shield: true,
        botDetection: true,
        rateLimiting: true,
      },
      request: {
        ip,
        userAgent,
        timestamp: new Date().toISOString(),
      },
    };

    // Log the event
    await logSecurityEvent({
      eventType: decision.isDenied() ? "THREAT_BLOCKED" : "THREAT_DETECTED",
      severity: decision.isDenied() ? "MEDIUM" : "LOW",
      sourceIP: ip,
      userAgent,
      endpoint: "/api/arcjet",
      action: decision.isDenied() ? "BLOCK" : "ALLOW",
      threatType: decision.isDenied() ? "ARCJET_PROTECTION" : undefined,
      metadata: {
        provider: "arcjet",
        conclusion: decision.conclusion,
        reason: decision.reason,
      },
    });

    if (decision.isDenied()) {
      return NextResponse.json(
        {
          ...response,
          message: "Request blocked by Arcjet WAF protection",
        },
        { status: 403 }
      );
    }

    return NextResponse.json({
      ...response,
      message: "Request allowed - Arcjet WAF protection active",
    });
  } catch (error) {
    console.error("Arcjet error:", error);
    return NextResponse.json(
      {
        status: "error",
        message: "Error checking Arcjet protection",
        error: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 }
    );
  }
}

export async function POST(request: NextRequest) {
  const ip = request.headers.get("x-forwarded-for") || "127.0.0.1";
  const userAgent = request.headers.get("user-agent") || "unknown";

  // If Arcjet is not configured, return graceful fallback
  if (!aj) {
    return NextResponse.json({
      status: "disabled",
      message: "Arcjet is not configured. Set ARCJET_KEY to enable WAF protection.",
    });
  }

  try {
    const body = await request.json().catch(() => ({}));

    // Run Arcjet protection check
    const decision = await aj.protect(request, { requested: 1 });

    const response = {
      status: decision.isDenied() ? "blocked" : "allowed",
      decision: {
        conclusion: decision.conclusion,
        reason: decision.reason,
        ruleResults: decision.results.map((r) => ({
          ruleId: r.ruleId,
          state: r.state,
          conclusion: r.conclusion,
        })),
      },
      payload: {
        received: !!body,
        keys: Object.keys(body),
      },
      request: {
        ip,
        userAgent,
        timestamp: new Date().toISOString(),
      },
    };

    // Log the event
    await logSecurityEvent({
      eventType: decision.isDenied() ? "THREAT_BLOCKED" : "THREAT_DETECTED",
      severity: decision.isDenied() ? "HIGH" : "LOW",
      sourceIP: ip,
      userAgent,
      endpoint: "/api/arcjet",
      payload: JSON.stringify(body).slice(0, 500),
      action: decision.isDenied() ? "BLOCK" : "ALLOW",
      threatType: decision.isDenied() ? "ARCJET_PROTECTION" : undefined,
      metadata: {
        provider: "arcjet",
        conclusion: decision.conclusion,
        reason: decision.reason,
        method: "POST",
      },
    });

    if (decision.isDenied()) {
      return NextResponse.json(
        {
          ...response,
          message: "Request blocked by Arcjet WAF protection",
          explanation:
            "Your request was flagged by one or more security rules (rate limit, bot detection, or shield protection).",
        },
        { status: 403 }
      );
    }

    return NextResponse.json({
      ...response,
      message: "Request allowed - Arcjet WAF protection verified",
      explanation:
        "Your request passed all security checks. Try sending multiple rapid requests to trigger rate limiting.",
    });
  } catch (error) {
    console.error("Arcjet POST error:", error);
    return NextResponse.json(
      {
        status: "error",
        message: "Error processing request",
        error: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 }
    );
  }
}
