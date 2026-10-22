/** Presentation only. The original result is always available verbatim. */
export function toolOutput(result: string) {
  const summary = /^\*\*PARSED SUMMARY:\*\* ([^\n]*)/m.exec(result)?.[1];
  const error = /^\*\*ERROR:\*\* ([^\n]*)/m.exec(result)?.[1]
    || /^ERROR: ([^\n]*)/m.exec(result)?.[1];
  const sections: {label: string; content: string}[] = [];
  for (const match of result.matchAll(/^\*\*(STDOUT|STDERR)\*\*[^\n]*\n```\n([\s\S]*?)^```\s*$/gm)) {
    sections.push({label: match[1] === "STDOUT" ? "Output" : "Diagnostics", content: match[2]!.trimEnd()});
  }
  const footer = result.lastIndexOf("\n---\n");
  const guidance = footer >= 0 ? result.slice(footer + 5).trim() : "";
  return {summary, error, sections, guidance};
}

/** Old transcripts can contain a success flag from an earlier formatter bug. */
export function outputFailed(result = ""): boolean {
  const flag = /^success:\s*(true|false)\b/im.exec(result);
  if (flag) return flag[1]!.toLowerCase() === "false";
  return /^ERROR:/m.test(result.split("```", 1)[0]!);
}
