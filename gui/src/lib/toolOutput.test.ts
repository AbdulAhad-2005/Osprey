import {expect, it} from "vitest";
import {outputFailed, toolOutput} from "./toolOutput";

it("separates raw evidence, diagnostics and guidance without changing their contents", () => {
  const result = '### OPERATOR MIRROR — EXECUTION\nsuccess: True\n**COMMAND:** `tool`\n**PARSED SUMMARY:** 2 hosts\n**STDOUT** (9 chars):\n```\nhost1\nhost2\n```\n**STDERR** (7 chars):\n```\nwarning\n```\n\n---\nChoose the next tool.';
  const parsed = toolOutput(result);
  expect(parsed.sections).toEqual([{label:"Output",content:"host1\nhost2"},{label:"Diagnostics",content:"warning"}]);
  expect(parsed.guidance).toBe("Choose the next tool.");
  expect(parsed.summary).toBe("2 hosts");
});

it("corrects historical transport success badges without interpreting target error bodies", () => {
  expect(outputFailed("### OPERATOR MIRROR — TIMEOUT\nERROR: Request timed out")).toBe(true);
  expect(outputFailed("success: True\n**STDOUT**:\n```\nERROR: target banner\n```")).toBe(false);
});
