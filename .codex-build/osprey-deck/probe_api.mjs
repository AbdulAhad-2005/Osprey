import { FileBlob, PresentationFile } from "@oai/artifact-tool";
const p = await PresentationFile.importPptx(await FileBlob.load(process.argv[2]));
const s = p.slides.items[0];
const sh = s.shapes.items[0];
const keys = (o) => [...new Set([...Object.keys(o ?? {}), ...Object.getOwnPropertyNames(Object.getPrototypeOf(o ?? {}))])];
console.log(JSON.stringify({
  presentation: keys(p),
  slides: keys(p.slides),
  slide: keys(s),
  shapes: keys(s.shapes),
  shape: keys(sh),
}, null, 2));
