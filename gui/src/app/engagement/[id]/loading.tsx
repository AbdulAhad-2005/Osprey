import { WorkspaceSkeleton } from "@/components/workspace/WorkspaceSkeleton";

// Route-level loading UI: shown while the segment's code/data resolve (including
// Next dev on-demand route compilation), so the first navigation to an
// engagement always commits to this instead of appearing stuck on the home page.
export default function Loading() {
  return <WorkspaceSkeleton />;
}
