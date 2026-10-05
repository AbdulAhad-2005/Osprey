import { FileBlob, PresentationFile } from "@oai/artifact-tool";

const sourcePath = process.argv[2];
const presentation = await PresentationFile.importPptx(await FileBlob.load(sourcePath));
const snapshot = await presentation.inspect({
  kind: "slide,textbox,shape,image,table,chart,notes,layout",
  maxChars: 50000,
});
console.log(JSON.stringify({
  slideCount: presentation.slides.items.length,
  masters: presentation.masters.items.map((m) => ({ id: m.id, name: m.name })),
}));
console.log(snapshot.ndjson);
