"use client";

import { Suspense } from "react";
import { useParams } from "next/navigation";
import { EngagementWorkspace } from "@/components/workspace/EngagementWorkspace";
import { WorkspaceSkeleton } from "@/components/workspace/WorkspaceSkeleton";

export default function EngagementPage() {
  const params = useParams<{ id: string }>();
  const id = decodeURIComponent(params.id);
  // EngagementWorkspace reads useSearchParams(); Next requires it to sit inside a
  // Suspense boundary, otherwise the whole segment silently bails to client-only
  // rendering and a first client-side navigation can update the URL without ever
  // committing the new page (leaving the previous route mounted). The boundary
  // makes the route commit immediately to the skeleton, then swap in the content.
  return (
    <Suspense fallback={<WorkspaceSkeleton engagementId={id} />}>
      <EngagementWorkspace key={id} engagementId={id} />
    </Suspense>
  );
}
