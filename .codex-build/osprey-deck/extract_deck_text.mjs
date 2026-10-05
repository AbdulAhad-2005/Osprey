import { FileBlob, PresentationFile } from "@oai/artifact-tool";

const sourcePath = process.argv[2];
const presentation = await PresentationFile.importPptx(await FileBlob.load(sourcePath));

for (let index = 0; index < presentation.slides.items.length; index += 1) {
  const slide = presentation.slides.items[index];
  const snapshot = await presentation.inspect({
    kind: "textbox",
    scope: { slideIds: [slide.id] },
    maxChars: 30000,
  });
  const texts = [];
  for (const line of snapshot.ndjson.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      const item = JSON.parse(line);
      const text = item?.text ?? item?.props?.text ?? item?.content?.text;
      if (typeof text === "string" && text.trim()) texts.push(text.trim());
    } catch {}
  }
  console.log(`\n===== SLIDE ${index + 1} (${slide.id}) =====`);
  console.log([...new Set(texts)].join("\n"));
}
