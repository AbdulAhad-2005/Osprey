import { FileBlob, PresentationFile } from "@oai/artifact-tool";
const p = await PresentationFile.importPptx(await FileBlob.load(process.argv[2]));
const s = p.slides.items[Number(process.argv[3]) - 1];
const keys = (o) => [...new Set([...Object.keys(o ?? {}), ...Object.getOwnPropertyNames(Object.getPrototypeOf(o ?? {}))])];
console.log(JSON.stringify({ tables: keys(s.tables), count: s.tables.items.length, table: keys(s.tables.items[0]) }, null, 2));
