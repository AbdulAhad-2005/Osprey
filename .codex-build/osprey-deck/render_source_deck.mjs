import { FileBlob, PresentationFile } from "@oai/artifact-tool";
import fs from "node:fs/promises";
import path from "node:path";

const [sourcePath, outputDir] = process.argv.slice(2);
await fs.mkdir(outputDir, { recursive: true });
const presentation = await PresentationFile.importPptx(await FileBlob.load(sourcePath));

for (let index = 0; index < presentation.slides.items.length; index += 1) {
  const slide = presentation.slides.items[index];
  const rendered = await presentation.export({ slide, format: "png", scale: 0.55 });
  const name = `slide-${String(index + 1).padStart(2, "0")}.png`;
  await fs.writeFile(path.join(outputDir, name), Buffer.from(await rendered.arrayBuffer()));
  console.log(name);
}
