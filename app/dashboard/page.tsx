import { getSupabaseServer } from "../../lib/supabase-server";
import DashboardClient, { type DashboardStats, type SecurityEventRow } from "./dashboard-client";

const EMPTY_DASHBOARD_STATS: DashboardStats = {
  totalRequests: 0,
  allowed: 0,
  blocked: 0,
  rateLimited: 0,
  botDetections: 0,
  shieldTriggers: 0,
  uniqueIps: 0,
  arcjetBlocks: 0,
  arcjetRateLimits: 0,
  arcjetBots: 0,
  activeAlerts: 0,
  threatsByType: {},
};

function groupBy<T, K extends string | number | symbol>(items: T[], getKey: (item: T) => K) {
  return items.reduce(
    (acc, item) => {
      const key = getKey(item);
      (acc as Record<K, number>)[key] = ((acc as Record<K, number>)[key] || 0) + 1;
      return acc;
    },
    {} as Record<K, number>,
  );
}

export default async function DashboardPage() {
  const supabase = getSupabaseServer();

  if (!supabase) {
    return <DashboardClient events={[]} liveConnected={false} stats={EMPTY_DASHBOARD_STATS} />;
  }

  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const { data, error } = await supabase
    .from("security_events")
    .select("id, event_type, severity, threat_type, action, endpoint, source_ip, user_agent, timestamp, metadata")
    .gte("timestamp", since)
    .order("timestamp", { ascending: false })
    .limit(100);

  if (error) console.error("Error loading security_events", error);

  const events: SecurityEventRow[] = (data as SecurityEventRow[]) || [];
  const threatsByType = groupBy(events, (event) => event.threat_type || "UNKNOWN");
  const actions = groupBy(events, (event) => event.action);
  const arcjetEvents = events.filter((event) => event.metadata?.provider === "arcjet");
  const highPriorityEvents = events.filter((event) => event.severity === "HIGH" || event.severity === "CRITICAL");
  const uniqueIps = new Set(events.map((event) => event.source_ip).filter((ip): ip is string => Boolean(ip))).size;

  const stats: DashboardStats = {
    totalRequests: events.length,
    allowed: (actions.ALLOW || 0) + (actions.CHALLENGE || 0),
    blocked: actions.BLOCK || 0,
    rateLimited: events.filter((event) => event.event_type === "RATE_LIMITED").length,
    botDetections: events.filter((event) => event.threat_type === "BOT_BEHAVIOR").length,
    shieldTriggers: events.filter((event) => event.event_type === "THREAT_DETECTED").length,
    uniqueIps,
    arcjetBlocks: arcjetEvents.filter((event) => event.action === "BLOCK").length,
    arcjetRateLimits: arcjetEvents.filter((event) => event.event_type === "RATE_LIMITED").length,
    arcjetBots: arcjetEvents.filter(
      (event) =>
        event.threat_type === "BOT_BEHAVIOR" ||
        (typeof event.metadata?.kind === "string" && event.metadata.kind.includes("bot")),
    ).length,
    activeAlerts: highPriorityEvents.length,
    threatsByType,
  };

  return <DashboardClient events={events} liveConnected={!error} stats={stats} />;
}
