import { Presentation } from "@oai/artifact-tool";
const p = Presentation.create({ slideSize: { width: 1920, height: 1080 } });
const r = p.help("*", { search: "internal hyperlink slide link action", include: ["index", "examples", "notes"], maxChars: 30000 });
console.log(r.ndjson);
