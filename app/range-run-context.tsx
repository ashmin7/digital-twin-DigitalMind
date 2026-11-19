"use client";

import { createContext, useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";

export interface RangeRun {
  id: string;
  scenarioId: string;
  title: string;
  threatType: string;
  timestamp: string;
  method: "GET" | "POST";
  path: string;
  sourceIp: string;
  destination: string;
  statusCode: number;
  transactionId: string;
  signal: string;
  response: string;
  outcome: string;
  severity: "LOW" | "MEDIUM" | "HIGH";
  action: "ALLOW" | "BLOCK" | "CHALLENGE";
  inputSummary: string;
  trace: string[];
}

type NewRangeRun = Omit<RangeRun, "id">;

type RangeRunContextValue = {
  runs: RangeRun[];
  addRun: (run: NewRangeRun) => void;
  clearRuns: () => void;
};

const RangeRunContext = createContext<RangeRunContextValue | null>(null);

export function RangeRunProvider({ children }: { children: ReactNode }) {
  const [runs, setRuns] = useState<RangeRun[]>([]);

  const addRun = useCallback((run: NewRangeRun) => {
    setRuns((current) => [
      { ...run, id: `${run.transactionId}-${current.length + 1}` },
      ...current,
    ].slice(0, 50));
  }, []);

  const clearRuns = useCallback(() => setRuns([]), []);
  const value = useMemo(() => ({ runs, addRun, clearRuns }), [runs, addRun, clearRuns]);

  return <RangeRunContext.Provider value={value}>{children}</RangeRunContext.Provider>;
}

export function useRangeRuns() {
  const context = useContext(RangeRunContext);
  if (!context) throw new Error("useRangeRuns must be used within RangeRunProvider");
  return context;
}
