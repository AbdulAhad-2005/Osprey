"use client";

import { motion } from "framer-motion";
import { OspreyMark } from "@/components/brand/OspreyMark";
import type { ChatActivity } from "@/hooks/useChat";

export function ActivityIndicator({ activity }: { activity: ChatActivity }) {
  const label =
    activity.kind === "preparing"
      ? activity.message
      : activity.kind === "waiting"
        ? `Still working with the model · ${Math.round(activity.elapsed)}s`
        : activity.kind === "working"
          ? "Running tools"
          : "Thinking";

  return (
    <div className="flex items-center gap-2.5 py-1">
      <motion.span
        animate={{ y: [0, -3, 0], rotate: [-2, 2, -2] }}
        transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
        className="opacity-90"
      >
        <OspreyMark size={22} />
      </motion.span>
      <span className="shimmer-text font-medium">{label}</span>
      <style jsx>{`
        .shimmer-text {
          font-size: 13.5px;
          background: linear-gradient(
            100deg,
            #94a2ba 30%,
            #f7b94e 50%,
            #94a2ba 70%
          );
          background-size: 200% 100%;
          -webkit-background-clip: text;
          background-clip: text;
          -webkit-text-fill-color: transparent;
          animation: osp-shimmer 1.8s linear infinite;
        }
        @keyframes osp-shimmer {
          to {
            background-position: -200% 0;
          }
        }
      `}</style>
    </div>
  );
}
