import { FileBlob, PresentationFile } from "@oai/artifact-tool";
const p = await PresentationFile.importPptx(await FileBlob.load(process.argv[2]));
const idx = Number(process.argv[3]) - 1;
const s = p.slides.items[idx];
for (const [i, sh] of s.shapes.items.entries()) {
  console.log(`\n--- ${i} ${sh.id} ${sh.type} ---`);
  console.log(JSON.stringify(sh.data, null, 2).slice(0, 12000));
}
