import { notFound } from "next/navigation";
import type { Metadata } from "next";
import ScenarioClient from "./scenario-client";
import { labScenarios } from "../scenarios";

type ScenarioPageProps = {
  params: Promise<{ scenario: string }>;
};

export async function generateMetadata({ params }: ScenarioPageProps): Promise<Metadata> {
  const { scenario: scenarioId } = await params;
  const scenario = labScenarios[scenarioId];

  return {
    title: scenario ? `${scenario.title} | Digital Twin III` : "Training scenario | Digital Twin III",
    description: scenario?.description ?? "A safe, local cybersecurity training simulation.",
  };
}

export default async function ScenarioPage({ params }: ScenarioPageProps) {
  const { scenario: scenarioId } = await params;
  const scenario = labScenarios[scenarioId];

  if (!scenario) notFound();

  return <ScenarioClient scenario={scenario} />;
}
