import arcjet, { detectBot, shield, tokenBucket } from "@arcjet/next";

const key = process.env.ARCJET_KEY;

if (!key) {
  console.warn("ARCJET_KEY is not set; Arcjet protection is disabled.");
}

export const aj = key
  ? arcjet({
      key,
      rules: [
        // Core WAF-style protection
        shield({ mode: "LIVE" }),
        // Bot detection: block all bots except search engines
        detectBot({
          mode: "LIVE",
          allow: ["CATEGORY:SEARCH_ENGINE"],
        }),
        // Token bucket rate limit for abusive traffic
        tokenBucket({
          mode: "LIVE",
          refillRate: 5,
          interval: 10,
          capacity: 10,
        }),
      ],
    })
  : null;
