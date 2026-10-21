import { Radar, Globe, ShieldAlert, Fingerprint, type LucideIcon } from "lucide-react";

/** Canonical quick-start intents, shared by the launch page and the chat landing. */
export interface Intent {
  icon: LucideIcon;
  label: string;
  prompt: string;
}

export const QUICK_INTENTS: Intent[] = [
  {
    icon: Radar,
    label: "Map the attack surface",
    prompt:
      "Map the full external attack surface — subdomains, live hosts, ports, services, and tech stack.",
  },
  {
    icon: Globe,
    label: "Recon + OSINT",
    prompt:
      "Run recon and passive OSINT: subdomains, sister domains, emails, people, and exposed infrastructure.",
  },
  {
    icon: ShieldAlert,
    label: "Full assessment",
    prompt:
      "Run a full assessment: recon, then vulnerability discovery against the live surface. Pause before any exploitation.",
  },
  {
    icon: Fingerprint,
    label: "Find exposures",
    prompt:
      "Hunt for exposed credentials, secrets, and misconfigurations across the known surface.",
  },
];

/**
 * A sensible default kickoff when the operator starts an engagement without
 * typing a prompt (the "just start" path). Recon-first, explicit pause before
 * anything intrusive — safe to fire on one click.
 */
export function kickoffPrompt(target?: string): string {
  const t = target ? ` of ${target}` : "";
  return (
    `Begin a full external assessment${t}. Start with reconnaissance: enumerate subdomains and ` +
    `sister domains from multiple sources, resolve them to hosts, and map live services, open ports, ` +
    `and the technology stack — widening the surface as new assets appear. Then move into vulnerability ` +
    `discovery against the live surface. Narrate findings as you go, and pause to ask me before any ` +
    `exploitation or destructive action.`
  );
}
