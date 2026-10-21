"use client";

import { Brain } from "lucide-react";
import type { ChatTurn, TurnBlock } from "@/lib/types";
import { OspreyMark } from "@/components/brand/OspreyMark";
import { Markdown } from "./Markdown";
import { ToolCallCard } from "./ToolCallCard";
import { QuestionPrompt } from "./QuestionPrompt";

export function TurnView({
  turn,
  onAnswer,
}: {
  turn: ChatTurn;
  onAnswer: (questionId: string, value: string) => void;
}) {
  if (turn.role === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-2xl rounded-br-md border border-border bg-surface-2 px-3.5 py-2.5 text-[14.5px] leading-relaxed text-ink">
          {turn.text}
        </div>
      </div>
    );
  }

  return (
    <div className="flex gap-3">
      <div className="mt-0.5 flex-none">
        <span className="grid h-7 w-7 place-items-center rounded-lg border border-border bg-surface">
          <OspreyMark size={18} />
        </span>
      </div>
      <div className="min-w-0 flex-1 space-y-2.5">
        {turn.blocks.length === 0 && turn.streaming && (
          <div className="text-[13px] text-ink-faint">…</div>
        )}
        {turn.blocks.map((b) => (
          <Block key={b.id} block={b} onAnswer={onAnswer} inactive={!turn.streaming} />
        ))}
      </div>
    </div>
  );
}

function Block({
  block,
  onAnswer,
  inactive,
}: {
  block: TurnBlock;
  onAnswer: (questionId: string, value: string) => void;
  inactive: boolean;
}) {
  switch (block.kind) {
    case "text":
      return <Markdown>{block.content}</Markdown>;

    case "thinking":
      return (
        <div className="flex gap-2 border-l-2 border-border pl-3 text-[13px] italic leading-relaxed text-ink-dim">
          <Brain size={13} className="mt-1 flex-none text-ink-faint" />
          <span>{block.content}</span>
        </div>
      );

    case "tools":
      return (
        <div className="space-y-1.5">
          {block.calls.map((c) => (
            <ToolCallCard key={c.id} call={c} />
          ))}
        </div>
      );

    case "question":
      return (
        <QuestionPrompt
          question={block.question}
          answered={block.answered}
          inactive={inactive}
          onAnswer={(v) => onAnswer(block.question.id, v)}
        />
      );

    default:
      return null;
  }
}
