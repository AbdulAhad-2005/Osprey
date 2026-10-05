import { FileBlob, PresentationFile } from "@oai/artifact-tool";

const p = await PresentationFile.importPptx(await FileBlob.load(process.argv[2]));
const s = p.slides.items[Number(process.argv[3]) - 1];
for (const [i, sh] of s.shapes.items.entries()) {
  let value = null;
  try { value = sh.text?.text ?? sh.text ?? null; } catch {}
  let frame = null;
  try { frame = sh.textFrame?.textRange?.text ?? sh.textFrame?.text ?? null; } catch {}
  console.log(i, sh.id, sh.name, JSON.stringify(value), JSON.stringify(frame), Object.keys(sh).join(","));
}
