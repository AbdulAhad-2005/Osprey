import { FileBlob, PresentationFile } from "@oai/artifact-tool";
const p = await PresentationFile.importPptx(await FileBlob.load(process.argv[2]));
const result = await p.inspect({kind:"slide,textbox,shape", search:process.argv[3], maxChars:12000});
console.log(result.ndjson);
