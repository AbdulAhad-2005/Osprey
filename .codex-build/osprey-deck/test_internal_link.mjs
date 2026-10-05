import { Presentation, PresentationFile } from "@oai/artifact-tool";
const p = Presentation.create({ slideSize: { width: 1280, height: 720 } });
const s1 = p.slides.add();
const s2 = p.slides.add();
const box = s1.shapes.add({ geometry: "textbox", position: { left: 100, top: 100, width: 300, height: 80 }, fill: "none", line: { fill: "none", width: 0 } });
box.text = "Go to slide 2";
box.text.get("Go to slide 2").link = { uri: s2.id, isExternal: false, action: "ppaction://hlinksldjump" };
await (await PresentationFile.exportPptx(p)).save(process.argv[2]);
console.log(JSON.stringify({s1:s1.id,s2:s2.id}));
