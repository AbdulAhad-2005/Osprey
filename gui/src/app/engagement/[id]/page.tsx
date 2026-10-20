"use client";

import { useParams } from "next/navigation";
import { EngagementWorkspace } from "@/components/workspace/EngagementWorkspace";

export default function EngagementPage() {
  const params = useParams<{ id: string }>();
  const id = decodeURIComponent(params.id);
  return <EngagementWorkspace engagementId={id} />;
}
