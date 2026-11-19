import DashboardClient, { type DashboardStats } from "./dashboard-client";

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

export default function DashboardPage() {
  return <DashboardClient events={[]} liveConnected={false} stats={EMPTY_DASHBOARD_STATS} />;
}
