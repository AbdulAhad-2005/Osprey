import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { FileBlob, PresentationFile } from "@oai/artifact-tool";
import JSZip from "jszip";

const { SKILL_DIR } = process.env;
if (!path.isAbsolute(SKILL_DIR ?? "")) throw new Error("Set absolute SKILL_DIR");
const { resolvePresentationFont } = await import(
  pathToFileURL(path.join(SKILL_DIR, "container_tools/artifact_tool_utils.mjs")).href,
);

const [sourcePath, outputPath] = process.argv.slice(2);
const deck = await PresentationFile.importPptx(await FileBlob.load(sourcePath));
const font = resolvePresentationFont();
const iconDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "tech-icons");
const techIcons = Object.fromEntries(await Promise.all(
  ["python", "fastapi", "postgresql", "docker", "kalilinux", "mcp", "githubactions", "bash"].map(
    async (name) => [name, new Uint8Array(await fs.readFile(path.join(iconDir, `${name}.svg`)))],
  ),
));

const C = {
  bg: "#F7F4EE", navy: "#123B63", blue: "#2C6693", cyan: "#79A9C8",
  ink: "#102B44", muted: "#354F63", teal: "#2D8B84", green: "#4F8B64",
  line: "#CAD6DE", white: "#FFFFFF",
};

function addText(slide, text, x, y, w, h, options = {}) {
  const requestedSize = options.fontSize ?? 28;
  const readableSize = requestedSize <= 18 ? requestedSize + 3 : requestedSize <= 24 ? requestedSize + 2 : requestedSize <= 30 ? requestedSize + 1 : requestedSize;
  const box = slide.shapes.add({
    geometry: "textbox",
    position: { left: x, top: y, width: w, height: h },
    fill: "none",
    line: { fill: "none", width: 0 },
  });
  box.text = text;
  box.text.style = {
    typeface: font, fontSize: readableSize, color: options.color ?? C.ink,
    bold: options.bold ?? false, alignment: options.align ?? "left",
    verticalAlignment: options.valign ?? "top", autoFit: "shrinkText", wrap: "square",
    lineSpacing: options.lineSpacing ?? 1.0,
    insets: { top: 0, right: 0, bottom: 0, left: 0 },
  };
  return box;
}

function addRect(slide, x, y, w, h, fill, stroke = "none", radius = true) {
  return slide.shapes.add({
    geometry: radius ? "roundRect" : "rect",
    position: { left: x, top: y, width: w, height: h },
    fill: { type: "solid", color: fill },
    line: { fill: stroke, width: stroke === "none" ? 0 : 2 },
  });
}

function addLine(slide, x, y, w, color = C.line, width = 2) {
  return slide.shapes.add({
    geometry: "line", position: { left: x, top: y, width: w, height: 0 },
    fill: "none", line: { fill: color, width },
  });
}

function addTechItem(slide, { icon, x, y, title, body, accent }) {
  addLine(slide, x, y + 142, 360);
  slide.images.add({
    blob: icon, contentType: "image/svg+xml", alt: `${title} technology icon`, fit: "contain",
    position: { left: x, top: y + 4, width: 82, height: 82 },
  });
  addText(slide, title, x + 108, y, 252, 40, { fontSize: 27, bold: true, color: C.navy });
  addText(slide, body, x + 108, y + 48, 252, 82, { fontSize: 20, color: C.muted });
  addRect(slide, x, y + 136, 92, 6, accent, "none", false);
}

const { slide } = deck.slides.insert({ after: deck.slides.items[8] });
slide.background.fill = C.bg;
addText(slide, "09 / IMPLEMENTATION STACK", 92, 46, 600, 30, { fontSize: 19, bold: true, color: C.teal });
addText(slide, "Tools and technologies", 92, 88, 1710, 86, { fontSize: 54, bold: true, color: C.navy });
addLine(slide, 92, 188, 1736);
addText(slide, "Technologies verified from the current Osprey repository", 92, 218, 1200, 42, { fontSize: 27, color: C.muted });
addText(slide, "CORE PLATFORM", 92, 278, 500, 34, { fontSize: 21, bold: true, color: C.teal });
addText(slide, "EXECUTION AND DELIVERY", 92, 590, 600, 34, { fontSize: 21, bold: true, color: C.teal });

const top = [
  ["python", "Python", "Core language. Rich and Prompt Toolkit power the operator CLI.", C.blue],
  ["fastapi", "FastAPI", "Backend API with live progress streaming to the CLI.", C.teal],
  ["postgresql", "PostgreSQL", "Durable storage for engagements, evidence and world-model state.", C.blue],
  ["docker", "Docker Compose", "Runs the backend, database and optional Kali toolbox.", C.cyan],
];
const bottom = [
  ["kalilinux", "Kali Linux", "Execution environment for Nmap, Nuclei, SQLmap and other security tools.", C.blue],
  ["mcp", "MCP", "Typed contract connecting the harness with each security tool.", C.ink],
  ["githubactions", "GitHub Actions", "Builds and publishes the reproducible Kali tool image.", C.cyan],
  ["bash", "Shell automation", "Bash and PowerShell support setup and one-off execution.", C.green],
];
top.forEach(([key, title, body, accent], i) => addTechItem(slide, { icon: techIcons[key], x: 92 + i * 420, y: 336, title, body, accent }));
bottom.forEach(([key, title, body, accent], i) => addTechItem(slide, { icon: techIcons[key], x: 92 + i * 420, y: 648, title, body, accent }));
addRect(slide, 92, 866, 1656, 82, C.navy);
addText(slide, "Optional AI connectivity uses LiteLLM so the harness can work with multiple model providers.", 128, 887, 1584, 42, { fontSize: 24, bold: true, color: C.white, align: "center", valign: "middle" });
addText(slide, "10", 1760, 1000, 68, 28, { fontSize: 18, bold: true, color: C.cyan, align: "right" });

for (const item of deck.slides.items) item.speakerNotes.textFrame.setText("");

await fs.mkdir(path.dirname(outputPath), { recursive: true });
await (await PresentationFile.exportPptx(deck)).save(outputPath);

const zip = await JSZip.loadAsync(await fs.readFile(outputPath));
const presentationXml = await zip.file("ppt/presentation.xml").async("string");
const relsXml = await zip.file("ppt/_rels/presentation.xml.rels").async("string");
const relationshipMap = new Map();
for (const match of relsXml.matchAll(/<Relationship\b[^>]*\/>/g)) {
  const id = match[0].match(/\bId="([^"]+)"/)?.[1];
  const target = match[0].match(/\bTarget="([^"]+)"/)?.[1];
  if (id && target) relationshipMap.set(id, target);
}
const orderedSlidePaths = [...presentationXml.matchAll(/<p:sldId\b[^>]*r:id="([^"]+)"[^>]*\/>/g)].map((match) => {
  const target = relationshipMap.get(match[1]);
  if (!target) return null;
  if (target.startsWith("/")) return target.slice(1);
  return `ppt/${target.replace(/^\.\.\//, "")}`;
});

const renumber = [
  { index: 10, heading: ["09 / DELIVERY PLAN", "10 / DELIVERY PLAN"], page: ["10", "11"] },
  { index: 11, heading: ["10 / TEAM", "11 / TEAM"], page: ["11", "12"] },
  { index: 12, heading: ["11 / IMPACT", "12 / IMPACT"], page: ["12", "13"] },
];
for (const change of renumber) {
  const slidePath = orderedSlidePaths[change.index];
  const entry = slidePath && zip.file(slidePath);
  if (!entry) throw new Error(`Unable to resolve slide ${change.index + 1}`);
  let xml = await entry.async("string");
  xml = xml.replace(`<a:t>${change.heading[0]}</a:t>`, `<a:t>${change.heading[1]}</a:t>`);
  xml = xml.replace(`<a:t>${change.page[0]}</a:t>`, `<a:t>${change.page[1]}</a:t>`);
  zip.file(slidePath, xml);
}

for (const slidePath of orderedSlidePaths.filter(Boolean)) {
  const entry = zip.file(slidePath);
  let xml = await entry.async("string");
  if (!xml.includes("<p:transition")) xml = xml.replace("</p:sld>", '<p:transition spd="med" advClick="1"><p:fade/></p:transition></p:sld>');
  zip.file(slidePath, xml);
}

await fs.writeFile(outputPath, await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" }));
console.log(outputPath);
