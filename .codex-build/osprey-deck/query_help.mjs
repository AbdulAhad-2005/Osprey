import { Presentation } from "@oai/artifact-tool";
const presentation = Presentation.create({ slideSize: { width: 1920, height: 1080 } });
const result = presentation.help("*", {
  search: "delete remove clear shape collection slide shapes",
  include: ["index", "examples", "notes"],
  maxChars: 20000,
});
console.log(result.ndjson);
