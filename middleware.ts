import { NextRequest, NextResponse } from "next/server";
import { isSpoofedBot } from "@arcjet/inspect";
import { aj } from "./lib/arcjet";
import { logSecurityEvent } from "./lib/audit-logger";

export const config = {
  matcher: ["/api/:path*"],
};

export default async function middleware(request: NextRequest) {
  // If Arcjet is not configured, just continue as normal.
  if (!aj) {
    return NextResponse.next();
  }

  const decision = await aj.protect(request, { requested: 5 });
  const ip = request.headers.get("x-forwarded-for") || "unknown";
  const userAgent = request.headers.get("user-agent") || "unknown";
  const endpoint = request.nextUrl.pathname;

  if (decision.isDenied()) {
    if (decision.reason.isRateLimit()) {
      await logSecurityEvent({
        eventType: "RATE_LIMITED",
        severity: "MEDIUM",
        sourceIP: ip,
        userAgent,
        endpoint,
        action: "BLOCK",
        threatType: "BOT_BEHAVIOR",
        metadata: { provider: "arcjet", kind: "rate_limit" },
      });
      return NextResponse.json(
        { error: "Too Many Requests", reason: decision.reason },
        { status: 429 },
      );
    }
    if (decision.reason.isBot()) {
      await logSecurityEvent({
        eventType: "THREAT_BLOCKED",
        severity: "HIGH",
        sourceIP: ip,
        userAgent,
        endpoint,
        action: "BLOCK",
        threatType: "BOT_BEHAVIOR",
        metadata: { provider: "arcjet", kind: "bot" },
      });
      return NextResponse.json(
        { error: "No bots allowed", reason: decision.reason },
        { status: 403 },
      );
    }
    await logSecurityEvent({
      eventType: "THREAT_BLOCKED",
      severity: "HIGH",
      sourceIP: ip,
      userAgent,
      endpoint,
      action: "BLOCK",
      threatType: "WAF_SHIELD",
      metadata: { provider: "arcjet", kind: "shield" },
    });
    return NextResponse.json(
      { error: "Forbidden", reason: decision.reason },
      { status: 403 },
    );
  }

  // Extra hardening based on IP / spoofed bot signals
  if (decision.ip.isHosting()) {
    await logSecurityEvent({
      eventType: "THREAT_BLOCKED",
      severity: "HIGH",
      sourceIP: ip,
      userAgent,
      endpoint,
      action: "BLOCK",
      threatType: "HOSTING_PROVIDER",
      metadata: { provider: "arcjet", kind: "hosting" },
    });
    return NextResponse.json(
      { error: "Forbidden", reason: decision.reason },
      { status: 403 },
    );
  }

  if (decision.results.some(isSpoofedBot)) {
    await logSecurityEvent({
      eventType: "THREAT_BLOCKED",
      severity: "HIGH",
      sourceIP: ip,
      userAgent,
      endpoint,
      action: "BLOCK",
      threatType: "BOT_BEHAVIOR",
      metadata: { provider: "arcjet", kind: "spoofed_bot" },
    });
    return NextResponse.json(
      { error: "Forbidden", reason: decision.reason },
      { status: 403 },
    );
  }

  return NextResponse.next();
}
