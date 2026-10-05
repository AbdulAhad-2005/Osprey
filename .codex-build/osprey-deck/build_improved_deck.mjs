import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { FileBlob, PresentationFile } from "@oai/artifact-tool";
import JSZip from "jszip";

const { SKILL_DIR, TMP_DIR } = process.env;
if (!path.isAbsolute(SKILL_DIR ?? "") || !path.isAbsolute(TMP_DIR ?? "")) {
  throw new Error("Set absolute SKILL_DIR and TMP_DIR");
}
const { resolvePresentationFont } = await import(
  pathToFileURL(path.join(SKILL_DIR, "container_tools/artifact_tool_utils.mjs")).href,
);

const [sourcePath, outputPath] = process.argv.slice(2);
const deck = await PresentationFile.importPptx(await FileBlob.load(sourcePath));
const font = resolvePresentationFont();
const architectureImage = new Uint8Array(await fs.readFile("C:/Users/Hp/Downloads/osprey-architecture.drawio.png"));
const phaseAgentsImage = new Uint8Array(await fs.readFile("C:/Users/Hp/AppData/Local/Temp/codex-clipboard-6b6e8979-86e3-414a-a80e-499fd55a72af.png"));
const howItWorksImage = new Uint8Array(await fs.readFile("C:/Users/Hp/AppData/Local/Temp/codex-clipboard-7382c910-f70b-4c0c-8cd1-8716b1fafbc1.png"));
const iconDir = path.join(path.dirname(fileURLToPath(import.meta.url)), "tech-icons");
const techIcons = Object.fromEntries(await Promise.all(
  ["python", "fastapi", "postgresql", "docker", "kalilinux", "mcp", "githubactions", "bash"].map(
    async (name) => [name, new Uint8Array(await fs.readFile(path.join(iconDir, `${name}.svg`)))],
  ),
));
deck.slides.insert(8);
// The original evidence-memory slide is no longer part of the requested deck.
deck.slides.remove(9);
// Add the verified implementation stack immediately before the delivery plan.
deck.slides.insert(9);

const C = {
  bg: "#F7F4EE",
  paper: "#FFFDF9",
  navy: "#123B63",
  blue: "#2C6693",
  cyan: "#79A9C8",
  pale: "#E6EEF3",
  ink: "#102B44",
  muted: "#354F63",
  teal: "#2D8B84",
  green: "#4F8B64",
  amber: "#D79A32",
  red: "#C55B48",
  line: "#CAD6DE",
  white: "#FFFFFF",
};

function addText(slide, text, x, y, w, h, options = {}) {
  const requestedSize = options.fontSize ?? 28;
  const readableSize = requestedSize <= 18
    ? requestedSize + 3
    : requestedSize <= 24
      ? requestedSize + 2
      : requestedSize <= 30
        ? requestedSize + 1
        : requestedSize;
  const box = slide.shapes.add({
    geometry: "textbox",
    position: { left: x, top: y, width: w, height: h },
    fill: "none",
    line: { fill: "none", width: 0 },
  });
  box.text = text;
  box.text.style = {
    typeface: font,
    fontSize: readableSize,
    color: options.color ?? C.ink,
    bold: options.bold ?? false,
    italic: options.italic ?? false,
    alignment: options.align ?? "left",
    verticalAlignment: options.valign ?? "top",
    autoFit: options.autoFit ?? "shrinkText",
    wrap: "square",
    lineSpacing: options.lineSpacing ?? 1.0,
    insets: options.insets ?? { top: 0, right: 0, bottom: 0, left: 0 },
  };
  return box;
}

function addRect(slide, x, y, w, h, fill = C.paper, stroke = C.line, radius = true) {
  return slide.shapes.add({
    geometry: radius ? "roundRect" : "rect",
    position: { left: x, top: y, width: w, height: h },
    fill: { type: "solid", color: fill },
    line: { fill: stroke, width: stroke === "none" ? 0 : 2 },
  });
}

function addLine(slide, x, y, w, h, color = C.line, width = 2) {
  return slide.shapes.add({
    geometry: "line",
    position: { left: x, top: y, width: w, height: h },
    fill: "none",
    line: { fill: color, width },
  });
}

function addArrow(slide, x, y, w = 44, h = 26, fill = C.cyan) {
  return slide.shapes.add({
    geometry: "rightArrow",
    position: { left: x, top: y, width: w, height: h },
    fill: { type: "solid", color: fill },
    line: { fill: "none", width: 0 },
  });
}

function addPill(slide, text, x, y, w, h, fill = C.pale, color = C.navy, fontSize = 20) {
  const pill = addRect(slide, x, y, w, h, fill, "none", true);
  pill.text = text;
  pill.text.style = {
    typeface: font, fontSize: fontSize + 2, bold: true, color,
    alignment: "center", verticalAlignment: "middle", autoFit: "shrinkText",
    insets: { top: 4, right: 8, bottom: 4, left: 8 },
  };
  return pill;
}

function addNavButton(slide, label, x, y, w, h, targetSlideNumber, fill = C.navy) {
  const button = addRect(slide, x, y, w, h, fill, "none", true);
  button.text = label;
  button.text.style = {
    typeface: font, fontSize: 25, bold: true, color: C.white,
    alignment: "center", verticalAlignment: "middle", autoFit: "shrinkText",
    insets: { top: 8, right: 16, bottom: 8, left: 16 },
  };
  button.text.get(label).link = {
    uri: `../slides/slide${targetSlideNumber}.xml`,
    isExternal: false,
    action: "ppaction://hlinksldjump",
  };
  return button;
}

function addDirectionalArrow(slide, direction, x, y, w, h, fill = C.cyan) {
  return slide.shapes.add({
    geometry: `${direction}Arrow`,
    position: { left: x, top: y, width: w, height: h },
    fill: { type: "solid", color: fill },
    line: { fill: "none", width: 0 },
  });
}

function addCard(slide, { x, y, w, h, title, body, accent = C.blue, fill = C.paper, titleSize = 25, bodySize = 20 }) {
  addRect(slide, x, y, w, h, fill, C.line, true);
  addRect(slide, x, y, 9, h, accent, "none", false);
  addText(slide, title, x + 28, y + 22, w - 52, 44, { fontSize: titleSize, bold: true, color: C.navy });
  addText(slide, body, x + 28, y + 78, w - 52, h - 96, { fontSize: bodySize, color: C.muted, lineSpacing: 1.05 });
}

function addTechItem(slide, { icon, x, y, title, body, accent = C.blue }) {
  addLine(slide, x, y + 142, 360, 0, C.line, 2);
  slide.images.add({
    blob: icon,
    contentType: "image/svg+xml",
    alt: `${title} technology icon`,
    fit: "contain",
    position: { left: x, top: y + 4, width: 82, height: 82 },
  });
  addText(slide, title, x + 108, y, 252, 40, { fontSize: 27, bold: true, color: C.navy });
  addText(slide, body, x + 108, y + 48, 252, 82, { fontSize: 20, color: C.muted, lineSpacing: 1.0 });
  addRect(slide, x, y + 136, 92, 6, accent, "none", false);
}

function baseSlide(slide, kicker, title, number) {
  slide.shapes.deleteAll();
  for (const table of [...slide.tables.items]) slide.tables.deleteById(table.id);
  slide.background.fill = C.bg;
  addText(slide, kicker, 92, 46, 600, 30, { fontSize: 19, bold: true, color: C.teal });
  addText(slide, title, 92, 88, 1710, 86, { fontSize: 54, bold: true, color: C.navy });
  addLine(slide, 92, 188, 1736, 0, C.line, 2);
  addText(slide, String(number).padStart(2, "0"), 1760, 1000, 68, 28, { fontSize: 18, bold: true, color: C.cyan, align: "right" });
}

function setNotes(slide, text) {
  slide.speakerNotes.textFrame.setText(text);
}

// Slide 1 — proposal cover.
{
  const s = deck.slides.items[0];
  s.shapes.deleteAll();
  s.background.fill = C.bg;
  addPill(s, "FYP PROPOSAL DEFENSE · WORKING TITLE", 92, 74, 430, 46, C.pale, C.teal, 18);
  addText(s, "Autonomous Web Security\nAssessment Framework", 92, 158, 920, 198, { fontSize: 66, bold: true, color: C.navy, lineSpacing: 0.94 });
  addText(s, "A proposed dual-mode pentesting harness for broad, evidence-driven testing", 96, 386, 870, 84, { fontSize: 28, color: C.muted, lineSpacing: 1.05 });
  addLine(s, 96, 500, 820, 0, C.line, 2);
  addText(s, "Muhammad Usman Hamed  ·  Abdul Ahad  ·  Obaid Ishtiaq Satti", 96, 534, 910, 44, { fontSize: 22, bold: true, color: C.ink });
  addText(s, "Advisor: Dr. Madiha Khalid    Co-Advisor: Dr. Mehdi Hussain", 96, 592, 910, 40, { fontSize: 20, color: C.muted });
  addText(s, "School of Electrical Engineering and Computer Science · NUST", 96, 648, 910, 38, { fontSize: 18, color: C.muted });

  addRect(s, 1080, 120, 740, 770, C.paper, C.line, true);
  addText(s, "AUTHORIZED TARGET", 1290, 164, 320, 36, { fontSize: 19, bold: true, color: C.teal, align: "center" });
  addPill(s, "domain / IP / scope", 1280, 214, 340, 54, C.pale, C.navy, 22);
  addArrow(s, 1430, 294, 44, 42, C.cyan);
  addRect(s, 1210, 364, 480, 190, C.navy, "none", true);
  addText(s, "UNIFIED HARNESS", 1250, 398, 400, 46, { fontSize: 32, bold: true, color: C.white, align: "center" });
  addText(s, "Deterministic methodology\n+ optional AI reasoning", 1260, 458, 380, 70, { fontSize: 22, color: "#DDEAF2", align: "center" });
  addArrow(s, 1430, 584, 44, 42, C.cyan);
  addPill(s, "Attack-surface map", 1128, 678, 210, 62, C.pale, C.navy, 18);
  addPill(s, "Verified evidence", 1345, 678, 210, 62, "#DDEEEB", C.teal, 18);
  addPill(s, "Structured report", 1562, 678, 210, 62, "#F4E8D0", C.amber, 18);
  addText(s, "Proposed system — not a completed product", 1190, 810, 520, 36, { fontSize: 19, italic: true, color: C.muted, align: "center" });
  setNotes(s, "Open by framing this as a proposal. The project name is still under consideration, so the deck uses a descriptive working title rather than treating Osprey as final branding.");
}

// Slide 2 — web security + Equifax case.
{
  const s = deck.slides.items[1];
  baseSlide(s, "01 / WHY THIS MATTERS", "Web security protects the entire exposed application surface", 2);
  addRect(s, 92, 230, 700, 308, C.navy, "none", true);
  addText(s, "WEB SECURITY", 132, 272, 300, 38, { fontSize: 22, bold: true, color: C.cyan });
  addText(s, "Find, validate and reduce weaknesses before attackers exploit them.", 132, 330, 610, 112, { fontSize: 36, bold: true, color: C.white, lineSpacing: 1.0 });
  addText(s, "The surface includes domains, services, applications, APIs, identities, third-party components and the data connecting them.", 132, 458, 610, 64, { fontSize: 20, color: "#DCE8F0", lineSpacing: 1.05 });

  addText(s, "CASE STUDY · EQUIFAX, 2017", 860, 240, 760, 38, { fontSize: 22, bold: true, color: C.red });
  addText(s, "A known web vulnerability became a large-scale breach", 860, 292, 860, 62, { fontSize: 34, bold: true, color: C.navy });
  addCard(s, { x: 860, y: 378, w: 280, h: 216, title: "Known flaw", body: "A critical Apache Struts vulnerability had a patch available.", accent: C.red });
  addCard(s, { x: 1164, y: 378, w: 280, h: 216, title: "Coverage failure", body: "The public dispute portal remained unpatched and verification did not catch it.", accent: C.amber });
  addCard(s, { x: 1468, y: 378, w: 280, h: 216, title: "Impact", body: "Personal information of about 147 million people was exposed.", accent: C.red });
  addRect(s, 92, 654, 1656, 206, "#E8EFF3", "none", true);
  addText(s, "The lesson", 128, 688, 250, 38, { fontSize: 23, bold: true, color: C.teal });
  addText(s, "A single missed internet-facing asset can defeat security across a very large organisation. Effective testing must discover the full surface, verify coverage, and preserve evidence across every step.", 128, 742, 1550, 92, { fontSize: 29, bold: true, color: C.ink, lineSpacing: 1.0 });
  addText(s, "Sources: U.S. House Oversight Committee report (2018); U.S. Federal Trade Commission (2019).", 96, 918, 1460, 28, { fontSize: 15, color: C.muted });
  setNotes(s, "Explain that the Equifax breach was not caused by a lack of security tools. The organization had a patching process, but a complex legacy environment and failed verification left an internet-facing portal exposed. Official sources: https://oversight.house.gov/report/committee-releases-report-revealing-new-information-on-equifax-data-breach/ and https://www.ftc.gov/news-events/news/press-releases/2019/07/equifax-pay-575-million-part-settlement-ftc-cfpb-states-related-2017-data-breach");
}

// Slide 3 — existing tools and technologies with limitations.
{
  const s = deck.slides.items[2];
  baseSlide(s, "02 / CURRENT PRACTICE", "Existing tools and technologies", 3);
  addText(s, "Typical pentesting workflow", 92, 220, 520, 34, { fontSize: 23, bold: true, color: C.teal });
  const stages = ["Discover", "Resolve and probe", "Map services", "Test applications", "Validate and report"];
  stages.forEach((stage, i) => {
    addPill(s, stage, 92 + i * 334, 270, 290, 54, i < 2 ? "#DDEEEB" : i < 4 ? C.pale : "#F4E8D0", i < 2 ? C.teal : i < 4 ? C.navy : C.amber, 19);
    if (i < 4) addArrow(s, 392 + i * 334, 286, 34, 22, C.cyan);
  });

  const table = s.tables.add({
    rows: 4,
    columns: 4,
    left: 92,
    top: 370,
    width: 1656,
    height: 472,
    columnWidths: [300, 520, 360, 476],
    values: [
      ["Category", "Examples", "Strength", "Limitation"],
      ["Conventional security tools", "Subfinder, Amass, Nmap, Nuclei, SQLmap, ZAP, Metasploit", "Mature, specialized and repeatable", "Require manual coordination. Outputs remain disconnected and provide limited contextual reasoning."],
      ["AI pentesting agents", "PentestGPT, HackSynth, PentestAgent, AutoPentester, AutoAttacker, PentAGI, DarkMoon", "Adaptive planning and interpretation", "Depend on LLMs. Many evaluations use bounded tasks and provide limited broad reconnaissance coverage."],
      ["AI security frameworks", "HexStrike AI, pentestMCP, Shannon", "Centralized tool access and automation", "Tool access alone does not provide a complete workflow or persistent correlation across testing stages."],
    ],
  });
  table.rows[0].height = 64;
  table.rows[1].height = 126;
  table.rows[2].height = 156;
  table.rows[3].height = 126;
  table.borders.assign({ style: "solid", fill: C.line, width: 1.5 });
  for (let r = 0; r < 4; r += 1) {
    for (let c = 0; c < 4; c += 1) {
      const cell = table.getCell(r, c);
      cell.fill = r === 0 ? C.navy : r % 2 === 1 ? C.paper : "#EDF3F5";
      cell.text.style = {
        typeface: font,
        fontSize: r === 0 ? 24 : 22,
        bold: r === 0 || c === 0,
        color: r === 0 ? C.white : C.ink,
        verticalAlignment: "middle",
        autoFit: "shrinkText",
        insets: { top: 10, right: 12, bottom: 10, left: 12 },
      };
    }
  }
  addText(s, "Source: FYP defense report, literature review and comparison table, pp. 5–10.", 96, 900, 1380, 28, { fontSize: 15, color: C.muted });
  setNotes(s, "The workflow at the top shows the steps a tester normally performs. The table compares conventional tools, AI pentesting agents and AI security frameworks. Conventional tools are mature but fragmented. AI systems add reasoning, yet many depend on external models and do not provide broad, continuous reconnaissance or persistent cross-stage correlation.");
}

// Slide 4 — operational security gap.
{
  const s = deck.slides.items[3];
  baseSlide(s, "03 / THE GAP", "The operational security gap is orchestration at scale", 4);
  addText(s, "Practical limitations prevent current tools from covering large infrastructures as one connected assessment.", 92, 216, 1580, 44, { fontSize: 27, color: C.muted });
  addCard(s, { x: 92, y: 292, w: 512, h: 360, title: "1 · Fragmented workflow", body: "Specialized tools emit isolated outputs.\n\nHumans repeatedly copy, filter, correlate and decide what to run next.\n\nAssets, services, endpoints and evidence are easily disconnected.", accent: C.blue, titleSize: 28, bodySize: 22 });
  addCard(s, { x: 630, y: 292, w: 512, h: 360, title: "2 · Reconnaissance scale", body: "Real infrastructures are wider than bounded CTF tasks.\n\nEach new domain, host, port or endpoint creates more work.\n\nMany AI systems are not optimized for continuous, broad reconnaissance coverage.", accent: C.teal, titleSize: 28, bodySize: 22 });
  addCard(s, { x: 1168, y: 292, w: 580, h: 360, title: "3 · External LLM dependency", body: "API cost, rate limits, connectivity and model behavior can interrupt assessments.\n\nKnown pentesting steps do not require expensive reasoning every time.\n\nWhen the model stops, the core workflow should not stop.", accent: C.amber, titleSize: 28, bodySize: 22 });
  addRect(s, 92, 700, 1656, 154, "#F1E8DC", "none", true);
  addText(s, "Trust and control must span the entire workflow", 126, 730, 700, 38, { fontSize: 24, bold: true, color: C.red });
  addText(s, "Scope enforcement", 132, 792, 300, 32, { fontSize: 22, bold: true, color: C.ink });
  addText(s, "Evidence-based findings", 530, 792, 360, 32, { fontSize: 22, bold: true, color: C.ink });
  addText(s, "Human approval before impactful actions", 982, 792, 660, 32, { fontSize: 22, bold: true, color: C.ink });
  addText(s, "Source: FYP defense report, pp. 10–12.", 96, 918, 1000, 28, { fontSize: 15, color: C.muted });
  setNotes(s, "Use the phrase operational security gap. The central argument is not that the industry lacks scanners; it lacks a dependable harness that can coordinate them over a changing, wide attack surface while keeping evidence and scope intact. Emphasize that LLMs are valuable but should not be mandatory for routine methodology.");
}

// Slide 5 — project objectives.
{
  const s = deck.slides.items[4];
  baseSlide(s, "04 / PROJECT OBJECTIVES", "Objectives", 5);
  addCard(s, { x: 92, y: 266, w: 512, h: 450, title: "1 · Integrated security assessment", body: "Develop one unified harness covering reconnaissance, progressive attack-surface discovery, scanning, vulnerability identification, business-logic analysis, correlation and reporting.", accent: C.blue, titleSize: 29, bodySize: 23 });
  addCard(s, { x: 630, y: 266, w: 512, h: 450, title: "2 · Dual-mode orchestration", body: "Use LLM reasoning when available while maintaining a deterministic rule-based mode with no mandatory LLM dependency.", accent: C.teal, titleSize: 29, bodySize: 23 });
  addCard(s, { x: 1168, y: 266, w: 580, h: 450, title: "3 · Safe and controlled testing", body: "Enforce the authorized scope, validate findings with evidence and require human approval before potentially impactful actions.", accent: C.red, titleSize: 29, bodySize: 23 });
  addRect(s, 92, 770, 1656, 108, "#E8EFF3", "none", true);
  addText(s, "The proposed framework combines one unified harness, reliable non-LLM operation and controlled AI assistance.", 132, 800, 1576, 52, { fontSize: 28, bold: true, color: C.navy, align: "center", valign: "middle" });
  addText(s, "Source: FYP defense report, Objectives, p. 14.", 96, 918, 1000, 28, { fontSize: 15, color: C.muted });
  setNotes(s, "State the three formal objectives at a high level. The first objective creates one unified assessment harness. The second keeps the system functional without an external LLM. The third covers scope, evidence and human approval.");
}

// Slide 6 — architecture hub.
{
  const s = deck.slides.items[5];
  baseSlide(s, "05 / PROPOSED ARCHITECTURE", "THE WORLD MODEL FOR PENTESTING", 6);
  addRect(s, 72, 218, 1370, 738, C.white, C.line, true);
  s.images.add({
    blob: architectureImage,
    contentType: "image/png",
    alt: "Proposed architecture diagram showing the commander, shared memory, phase agents, reasoning loop, deterministic pipeline and skills",
    fit: "contain",
    position: { left: 88, top: 234, width: 1338, height: 706 },
  });
  addText(s, "EXPLORE THE MODEL", 1492, 256, 280, 34, { fontSize: 19, bold: true, color: C.teal, align: "center" });
  addNavButton(s, "World model?", 1474, 324, 320, 92, 7, C.teal);
  addNavButton(s, "Phase agents?", 1474, 458, 320, 92, 8, C.blue);
  addNavButton(s, "How will it all work?", 1474, 592, 320, 104, 9, C.navy);
  addText(s, "Select a question during the presentation to open its explanation.", 1480, 746, 308, 86, { fontSize: 18, color: C.muted, align: "center", valign: "middle" });
  setNotes(s, "This is the proposed architecture. The central idea is a world model: every tool observation updates shared memory, specialized agents act on that state, and both deterministic and reasoning-driven execution use the same tools and evidence. Use the three buttons for optional explanations, then return here.");
}

// Slide 7 — the pentester's world-model loop.
{
  const s = deck.slides.items[6];
  baseSlide(s, "06 / WORLD MODEL", "How a real pentester works", 7);
  addText(s, "THE WORLD MODEL FOR PENTESTING", 92, 218, 1710, 42, { fontSize: 25, bold: true, color: C.teal, align: "center" });

  const topNodes = [
    ["1", "Observe", "Collect signals from tools, targets and prior evidence.", C.teal],
    ["2", "Store in memory", "Preserve assets, observations, relationships and source evidence.", C.blue],
    ["3", "Form a hypothesis", "Explain what the evidence may mean and what could be vulnerable.", C.amber],
    ["4", "Test", "Choose the next useful probe and run the appropriate security tool.", C.red],
  ];
  topNodes.forEach(([n, title, body, accent], i) => {
    const x = 92 + i * 414;
    addCard(s, { x, y: 296, w: 374, h: 244, title: `${n} · ${title}`, body, accent, titleSize: 27, bodySize: 20 });
    if (i < 3) addDirectionalArrow(s, "right", x + 380, 398, 28, 30, C.cyan);
  });
  addDirectionalArrow(s, "down", 1662, 554, 34, 64, C.cyan);
  addCard(s, { x: 1260, y: 650, w: 488, h: 186, title: "5 · Validate", body: "Compare outcomes, reproduce the result and separate a lead from verified evidence.", accent: C.green, titleSize: 27, bodySize: 20 });
  addDirectionalArrow(s, "left", 1164, 716, 76, 36, C.cyan);
  addCard(s, { x: 630, y: 650, w: 510, h: 186, title: "6 · Update memory", body: "Record what changed, connect the evidence and revise what should be tested next.", accent: C.teal, titleSize: 27, bodySize: 20 });
  addDirectionalArrow(s, "left", 528, 716, 78, 36, C.cyan);
  addRect(s, 92, 650, 414, 186, C.navy, "none", true);
  addText(s, "Repeat", 124, 684, 350, 42, { fontSize: 30, bold: true, color: C.white, align: "center" });
  addText(s, "Updated memory changes what the tester observes and tests next.", 124, 742, 350, 68, { fontSize: 20, color: "#DCE8F0", align: "center", valign: "middle" });
  addDirectionalArrow(s, "up", 266, 562, 34, 64, C.cyan);
  addText(s, "The assessment is a continuous evidence loop—not a one-time scanner run.", 92, 898, 1480, 42, { fontSize: 27, bold: true, color: C.navy });
  addNavButton(s, "← Back to architecture", 1510, 886, 288, 64, 6, C.navy);
  setNotes(s, "A real pentester continuously observes, stores evidence, forms a hypothesis, tests it, validates the result and updates memory. That updated state changes the next decision. This loop is the world model that connects the architecture.");
}

// Slide 8 — phase agents.
{
  const s = deck.slides.items[7];
  baseSlide(s, "07 / PHASE AGENTS", "Specialized agents for each testing phase", 8);
  addText(s, "Standard pentest methodology is divided among specialized agents.", 92, 222, 1710, 44, { fontSize: 28, color: C.muted, align: "center" });
  addRect(s, 118, 312, 1604, 302, C.white, C.line, true);
  s.images.add({
    blob: phaseAgentsImage,
    contentType: "image/png",
    alt: "Reconnaissance, vulnerability and validation phase agents",
    fit: "contain",
    position: { left: 150, top: 350, width: 1540, height: 220 },
  });
  const descriptions = [
    ["Reconnaissance", "Maps the attack surface using discovery, DNS, probing and service-enumeration tools.", C.teal],
    ["Vulnerability", "Tests the mapped surface with network, web and vulnerability-analysis tools.", C.blue],
    ["Validation", "Confirms evidence and separates reproducible findings from scanner leads.", C.green],
  ];
  descriptions.forEach(([title, body, accent], i) => addCard(s, {
    x: 92 + i * 552, y: 680, w: 522, h: 194, title, body, accent, titleSize: 26, bodySize: 19,
  }));
  addText(s, "Each agent has its own tools and skill files, but all agents operate on the same shared memory.", 92, 914, 1370, 38, { fontSize: 24, bold: true, color: C.navy });
  addNavButton(s, "← Back to architecture", 1510, 898, 288, 64, 6, C.navy);
  setNotes(s, "The phase agents follow the standard pentesting methodology. Reconnaissance maps the surface, vulnerability assessment tests it, and validation confirms evidence before reporting. Each agent has appropriate tools and skills, while shared memory prevents the phases from becoming disconnected.");
}

// Slide 9 — deterministic execution with LLM oversight.
{
  const s = deck.slides.items[8];
  baseSlide(s, "08 / DUAL-MODE EXECUTION", "How will it all work?", 9);
  addRect(s, 118, 222, 1604, 410, C.white, C.line, true);
  s.images.add({
    blob: howItWorksImage,
    contentType: "image/png",
    alt: "Reasoning loop and deterministic pipeline using the same skill files",
    fit: "contain",
    position: { left: 148, top: 254, width: 1544, height: 346 },
  });
  addCard(s, { x: 92, y: 680, w: 800, h: 196, title: "1 · Deterministic methodology", body: "The battle-tested pentesting methodology runs through repeatable rules and tools without requiring an LLM.", accent: C.teal, titleSize: 28, bodySize: 21 });
  addCard(s, { x: 928, y: 680, w: 820, h: 196, title: "2 · LLM oversight", body: "The LLM oversees the assessment, performs contextual analysis and decides where deeper reasoning is useful.", accent: C.amber, titleSize: 28, bodySize: 21 });
  addText(s, "Skill files form the knowledge base for tools, techniques and phase-specific procedures.", 92, 914, 1370, 38, { fontSize: 24, bold: true, color: C.navy });
  addNavButton(s, "← Back to architecture", 1510, 898, 288, 64, 6, C.navy);
  setNotes(s, "Two execution paths use the same skills and evidence. The deterministic pipeline performs repeatable, battle-tested steps without an LLM. The LLM oversees the wider context and adds judgment where uncertainty or adaptive reasoning matters. Skill files provide the extensible knowledge base.");
}

// Slide 10 — verified implementation stack.
{
  const s = deck.slides.items[9];
  baseSlide(s, "09 / IMPLEMENTATION STACK", "Tools and technologies", 10);
  addText(s, "Technologies verified from the current Osprey repository", 92, 218, 1200, 42, { fontSize: 27, color: C.muted });
  addText(s, "CORE PLATFORM", 92, 278, 500, 34, { fontSize: 21, bold: true, color: C.teal });
  addText(s, "EXECUTION AND DELIVERY", 92, 590, 600, 34, { fontSize: 21, bold: true, color: C.teal });

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
  top.forEach(([key, title, body, accent], i) => addTechItem(s, {
    icon: techIcons[key], x: 92 + i * 420, y: 336, title, body, accent,
  }));
  bottom.forEach(([key, title, body, accent], i) => addTechItem(s, {
    icon: techIcons[key], x: 92 + i * 420, y: 648, title, body, accent,
  }));
  addRect(s, 92, 866, 1656, 82, C.navy, "none", true);
  addText(s, "Optional AI connectivity uses LiteLLM so the harness can work with multiple model providers.", 128, 887, 1584, 42, { fontSize: 24, bold: true, color: C.white, align: "center", valign: "middle" });
}

// Slide 11 — planned timeline.
{
  const s = deck.slides.items[10];
  baseSlide(s, "10 / DELIVERY PLAN", "Planned timeline and milestones", 11);
  addText(s, "September 2026 → April 2027", 92, 216, 720, 42, { fontSize: 27, color: C.muted });
  const plan = [
    ["SEP", "Planning &\narchitecture", C.navy],
    ["OCT", "Recon", C.teal],
    ["NOV", "Network & web\nassessment", C.blue],
    ["DEC", "Integration &\ncorrelation", C.green],
    ["JAN", "Business logic\n& safety", C.red],
    ["FEB", "Dual-mode\norchestration", C.amber],
    ["MAR", "Testing &\nrefinement", C.blue],
    ["APR", "Evaluation &\ndefense", C.navy],
  ];
  addLine(s, 158, 438, 1510, 0, C.line, 6);
  plan.forEach(([month, label, color], i) => {
    const x = 92 + i * 207;
    addRect(s, x, 322, 174, 220, C.paper, C.line, true);
    addPill(s, month, x + 30, 346, 114, 48, color, C.white, 18);
    addText(s, label, x + 10, 426, 154, 82, { fontSize: 18, bold: true, color: C.ink, align: "center", valign: "middle" });
  });
  addRect(s, 92, 616, 1656, 236, "#E8EFF3", "none", true);
  addText(s, "Evaluation focus", 128, 650, 340, 38, { fontSize: 24, bold: true, color: C.teal });
  addCard(s, { x: 128, y: 690, w: 470, h: 142, title: "Coverage", body: "Attack-surface discovery and vulnerability coverage.", accent: C.teal, titleSize: 21, bodySize: 19 });
  addCard(s, { x: 624, y: 690, w: 470, h: 142, title: "Reliability", body: "Comparable operation with and without an LLM.", accent: C.blue, titleSize: 21, bodySize: 19 });
  addCard(s, { x: 1120, y: 690, w: 590, h: 142, title: "Safety and efficiency", body: "Zero scope violations and measurable time improvement.", accent: C.amber, titleSize: 21, bodySize: 19 });
  setNotes(s, "Present this as the planned schedule. The final evaluation will compare coverage, reliability across both modes, safety controls and time efficiency against manual baselines.");
}

// Slide 12 — team responsibilities.
{
  const s = deck.slides.items[11];
  baseSlide(s, "11 / TEAM", "Team responsibilities and shared ownership", 12);
  addCard(s, { x: 92, y: 266, w: 512, h: 348, title: "Abdul Ahad", body: "Primary responsibility\n\nSystem architecture\nAI orchestration\nMethodology integration", accent: C.teal, titleSize: 31, bodySize: 23 });
  addCard(s, { x: 630, y: 266, w: 512, h: 348, title: "Muhammad Usman Hamed", body: "Primary responsibility\n\nReconnaissance\nSecurity assessment\nTool evaluation", accent: C.blue, titleSize: 29, bodySize: 23 });
  addCard(s, { x: 1168, y: 266, w: 580, h: 348, title: "Obaid Ishtiaq Satti", body: "Primary responsibility\n\nPlatform and interface\nReporting\nDeployment support", accent: C.amber, titleSize: 30, bodySize: 23 });
  addRect(s, 92, 668, 1656, 214, C.navy, "none", true);
  addText(s, "Shared across the team", 128, 704, 420, 42, { fontSize: 25, bold: true, color: C.cyan });
  const shared = ["Integration", "Testing", "Validation", "Debugging", "Performance evaluation", "Documentation"];
  shared.forEach((item, i) => addPill(s, item, 128 + (i % 3) * 500, 770 + Math.floor(i / 3) * 60, 440, 44, "#E8EFF3", C.navy, 19));
  setNotes(s, "Clarify that the primary areas identify ownership, not silos. Integration, testing, validation, debugging, evaluation and documentation remain shared responsibilities.");
}

// Slide 13 — users and SDGs.
{
  const s = deck.slides.items[12];
  baseSlide(s, "12 / IMPACT", "Who will use the proposed system?", 13);
  const users = [
    ["Penetration testing firms", "Repeatable external assessments across wide client surfaces.", C.blue],
    ["Internal security teams", "Continuous visibility and evidence across changing infrastructure.", C.teal],
    ["Managed security providers", "Standardized multi-engagement execution and reporting.", C.amber],
    ["DevSecOps teams", "Security assessment integrated into engineering workflows.", C.green],
  ];
  users.forEach(([title, body, accent], i) => addCard(s, { x: 92 + i * 414, y: 260, w: 388, h: 286, title, body, accent, titleSize: 26, bodySize: 21 }));
  addText(s, "UN Sustainable Development Goal alignment", 92, 614, 900, 40, { fontSize: 25, bold: true, color: C.teal });
  addCard(s, { x: 92, y: 682, w: 512, h: 178, title: "SDG 9", body: "Industry, innovation and resilient infrastructure.", accent: C.blue, titleSize: 28, bodySize: 21 });
  addCard(s, { x: 630, y: 682, w: 512, h: 178, title: "SDG 16", body: "Stronger institutions through improved cyber resilience.", accent: C.teal, titleSize: 28, bodySize: 21 });
  addCard(s, { x: 1168, y: 682, w: 580, h: 178, title: "SDG 17", body: "Partnerships through interoperable, open security tooling.", accent: C.amber, titleSize: 28, bodySize: 21 });
  setNotes(s, "The primary users are professional security teams. The SDG mapping is supportive context: resilient infrastructure, stronger institutions and interoperable partnerships.");
}

// Slide 14 — closing.
{
  const s = deck.slides.items[13];
  s.shapes.deleteAll();
  s.background.fill = C.bg;
  addPill(s, "FYP PROPOSAL DEFENSE", 92, 76, 286, 46, C.pale, C.teal, 18);
  addText(s, "Thank you", 92, 188, 900, 120, { fontSize: 78, bold: true, color: C.navy });
  addText(s, "Questions and discussion", 96, 328, 900, 56, { fontSize: 34, color: C.muted });
  addLine(s, 96, 416, 820, 0, C.line, 2);
  addText(s, "Proposed autonomous web security assessment framework", 96, 454, 920, 44, { fontSize: 24, bold: true, color: C.ink });
  addText(s, "Working title · proposed architecture · planned evaluation", 96, 516, 920, 38, { fontSize: 21, color: C.muted });

  addRect(s, 1100, 142, 650, 690, C.navy, "none", true);
  addText(s, "DISCUSSION", 1160, 202, 530, 36, { fontSize: 20, bold: true, color: C.cyan, align: "center" });
  addText(s, "How can a pentesting harness remain useful when AI is unavailable?", 1170, 280, 510, 160, { fontSize: 38, bold: true, color: C.white, align: "center", valign: "middle", lineSpacing: 1.0 });
  addPill(s, "Methodology", 1180, 514, 220, 58, "#E5F0EC", C.teal, 20);
  addPill(s, "Evidence", 1450, 514, 220, 58, C.pale, C.navy, 20);
  addPill(s, "Human control", 1180, 608, 490, 58, "#F4E8D0", C.amber, 20);
  addText(s, "Muhammad Usman Hamed · Abdul Ahad · Obaid Ishtiaq Satti", 1120, 752, 610, 34, { fontSize: 17, color: "#DCE8F0", align: "center" });
  setNotes(s, "Invite questions. If asked whether the system already exists, clarify that this defense presents the proposed architecture and planned implementation; the project name is still a working title.");
}

async function patchInternalSlideLinks(pptxPath) {
  const zip = await JSZip.loadAsync(await fs.readFile(pptxPath));
  for (const name of Object.keys(zip.files)) {
    const entry = zip.file(name);
    if (!entry) continue;
    if (/^ppt\/slides\/slide\d+\.xml$/.test(name)) {
      let xml = await entry.async("string");
      // Put navigation on the entire button shape. This prevents PowerPoint's
      // hyperlink theme from recoloring the visible white button label.
      xml = xml.replace(/<p:sp>[\s\S]*?<\/p:sp>/g, (shapeXml) => {
        const match = shapeXml.match(/<a:hlinkClick\b[^>]*action="ppaction:\/\/hlinksldjump"[^>]*\/>/);
        if (!match) return shapeXml;
        const sourceClick = match[0];
        const click = sourceClick.replace(
          "<a:hlinkClick",
          '<a:hlinkClick xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"',
        );
        const withoutTextLink = shapeXml.replace(sourceClick, "");
        return withoutTextLink.replace(/(<p:cNvPr\b[^>]*>)/, `$1${click}`);
      });
      // A restrained fade keeps the defense presentation polished without
      // distracting object-by-object motion.
      if (!xml.includes("<p:transition")) {
        xml = xml.replace("</p:sld>", '<p:transition spd="med" advClick="1"><p:fade/></p:transition></p:sld>');
      }
      zip.file(name, xml);
      continue;
    }
    if (!/^ppt\/slides\/_rels\/slide\d+\.xml\.rels$/.test(name)) continue;
    let xml = await entry.async("string");
    xml = xml.replace(
      /Type="http:\/\/schemas\.openxmlformats\.org\/officeDocument\/2006\/relationships\/hyperlink" Target="(\.\.\/slides\/slide\d+\.xml)"/g,
      'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="$1"',
    );
    zip.file(name, xml);
  }
  const bytes = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
  await fs.writeFile(pptxPath, bytes);
}

for (const slide of deck.slides.items) {
  slide.speakerNotes.textFrame.setText("");
}

await fs.mkdir(path.dirname(outputPath), { recursive: true });
await (await PresentationFile.exportPptx(deck)).save(outputPath);
await patchInternalSlideLinks(outputPath);
console.log(outputPath);
