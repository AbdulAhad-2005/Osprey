import { clsx } from "clsx";
import { OspreyMark } from "./OspreyMark";

/**
 * The "osprey" wordmark — set in the display serif, tight and lowercase, to
 * echo the logo's custom type. Kept as a separate export so it can be used on
 * its own (per brand guidance the mark and the wordmark each stand alone).
 */
export function OspreyWordmark({
  className,
  size = "md",
}: {
  className?: string;
  size?: "sm" | "md" | "lg";
}) {
  const scale = size === "sm" ? "text-[18px]" : size === "lg" ? "text-[27px]" : "text-[22px]";
  return (
    <span
      className={clsx(
        "font-display font-bold lowercase tracking-[-0.01em] text-ink leading-none",
        scale,
        className,
      )}
    >
      osprey
    </span>
  );
}

/** Mark + wordmark lockup. */
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
  return (
    <span className={clsx("inline-flex items-center gap-2.5", className)}>
      <OspreyMark size={markSize} />
      {showWordmark && <OspreyWordmark size={size} />}
    </span>
  );
}
