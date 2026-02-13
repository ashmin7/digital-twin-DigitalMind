import { NextRequest, NextResponse } from "next/server";
import { isSpoofedBot } from "@arcjet/inspect";
import { aj } from "./lib/arcjet";

export const config = {
  matcher: ["/api/:path*"],
};

export default async function middleware(request: NextRequest) {
  // If Arcjet is not configured, just continue as normal.
  if (!aj) {
    return NextResponse.next();
  }

  const decision = await aj.protect(request, { requested: 5 });

  if (decision.isDenied()) {
    if (decision.reason.isRateLimit()) {
      return NextResponse.json(
        { error: "Too Many Requests", reason: decision.reason },
        { status: 429 },
      );
    }
    if (decision.reason.isBot()) {
      return NextResponse.json(
        { error: "No bots allowed", reason: decision.reason },
        { status: 403 },
      );
    }
    return NextResponse.json(
      { error: "Forbidden", reason: decision.reason },
      { status: 403 },
    );
  }

  // Extra hardening based on IP / spoofed bot signals
  if (decision.ip.isHosting()) {
    return NextResponse.json(
      { error: "Forbidden", reason: decision.reason },
      { status: 403 },
    );
  }

  if (decision.results.some(isSpoofedBot)) {
    return NextResponse.json(
      { error: "Forbidden", reason: decision.reason },
      { status: 403 },
    );
  }

  return NextResponse.next();
}
