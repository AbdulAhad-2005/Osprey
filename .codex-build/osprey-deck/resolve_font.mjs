import path from "node:path";
import { pathToFileURL } from "node:url";
const { resolvePresentationFont } = await import(pathToFileURL(path.join(process.env.SKILL_DIR, "container_tools/artifact_tool_utils.mjs")).href);
console.log(resolvePresentationFont());
