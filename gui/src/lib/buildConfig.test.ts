import { describe, expect, it, afterEach, vi } from "vitest";
import config from "../../next.config.mjs";
import {
  PHASE_DEVELOPMENT_SERVER,
  PHASE_PRODUCTION_BUILD,
  PHASE_PRODUCTION_SERVER,
} from "next/constants.js";

afterEach(() => vi.unstubAllEnvs());
describe("Next output isolation", () => {
  it("build and start share output without overwriting a live dev server", () => {
    vi.stubEnv("OSPREY_NEXT_DIST", "");
    expect(config(PHASE_DEVELOPMENT_SERVER).distDir).toBe(".next-dev");
    expect(config(PHASE_PRODUCTION_BUILD).distDir).toBe(".next");
    expect(config(PHASE_PRODUCTION_SERVER).distDir).toBe(".next");
  });
  it("retains an explicit isolated test output override", () => {
    vi.stubEnv("OSPREY_NEXT_DIST", ".pytest-tmp/review");
    expect(config(PHASE_DEVELOPMENT_SERVER).distDir).toBe(".pytest-tmp/review");
  });
});
