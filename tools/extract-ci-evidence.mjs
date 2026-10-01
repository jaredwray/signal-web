#!/usr/bin/env node
// Recovers evidence files printed by tools/print-evidence.mjs from a
// downloaded GitHub Actions job log:
//   node tools/extract-ci-evidence.mjs <job-log.txt> <output-dir> [run-url]
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';

const [log, outDir, runUrl] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
let n = 0;
for (const line of readFileSync(log, 'utf8').split('\n')) {
  const m = line.match(/EVIDENCE_FILE (\S+) (\{.*\})\s*$/);
  if (!m) continue;
  const data = JSON.parse(m[2]);
  if (runUrl) data.ci_run = runUrl;
  writeFileSync(join(outDir, basename(m[1])), JSON.stringify(data, null, 2) + '\n');
  n += 1;
}
console.log(`extracted ${n} evidence files into ${outDir}`);
