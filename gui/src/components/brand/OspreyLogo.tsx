import { clsx } from "clsx";
import { OspreyMark } from "./OspreyMark";
import { BRAND } from "@/lib/brand";

/**
 * The product wordmark — set in the UI sans, semibold and tightly tracked.
 * Kept as a separate export so it can be used on its own.
 */
export function OspreyWordmark({
  className,
  size = "md",
}: {
  className?: string;
  size?: "sm" | "md" | "lg";
}) {
  const scale = size === "sm" ? "text-[16px]" : size === "lg" ? "text-[26px]" : "text-[18px]";
  return (
    <span className={clsx("font-semibold tracking-[-0.02em] text-ink leading-none", scale, className)}>
      {BRAND}
    </span>
  );
}

/** Mark + wordmark lockup. The mark sits on a fixed deep-navy tile so the
 *  brand artwork reads identically on light and dark surfaces. */
export function OspreyLogo({
  className,
  markSize = 30,
  size = "md",
  showWordmark = true,
}: {
  className?: string;
  markSize?: number;
  size?: "sm" | "md" | "lg";
  showWordmark?: boolean;
}) {
  const tile = Math.round(markSize * 1.45);
  return (
    <span className={clsx("inline-flex items-center gap-2.5", className)}>
      <span
        className="grid flex-none place-items-center rounded-[9px] bg-[#16213a] shadow-card ring-1 ring-inset ring-white/10"
        style={{ width: tile, height: tile }}
      >
        <OspreyMark size={markSize} />
      </span>
      {showWordmark && <OspreyWordmark size={size} />}
    </span>
  );
}
