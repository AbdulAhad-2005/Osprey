"use client";

import { useParams, useSearchParams } from "next/navigation";
import { ChatView } from "@/components/chat/ChatView";
import { useWorkspace } from "@/components/shell/WorkspaceProvider";

export default function EngagementPage() {
  const params = useParams<{ id: string }>();
  const search = useSearchParams();
  const { engagements } = useWorkspace();

  const id = decodeURIComponent(params.id);
  const engagement = engagements.find((e) => e.id === id);
  const initialPrompt = search.get("intent") ?? undefined;

  return (
    <ChatView
      engagementId={id}
      engagement={engagement}
      initialPrompt={initialPrompt}
    />
  );
}
