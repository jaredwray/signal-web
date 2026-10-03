#!/usr/bin/env node
// Prints evidence JSON files as single marked lines so they can be recovered
// verbatim from CI logs:  EVIDENCE_FILE <path> <compact json>
// Bulky raw test-runner output is dropped (per-test statuses are kept).
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith('.json') ? [p] : [];
  });
}

for (const dir of process.argv.slice(2)) {
  let files = [];
  try { files = walk(dir); } catch { continue; }
  for (const file of files) {
    const data = JSON.parse(readFileSync(file, 'utf8'));
    for (const r of data.results ?? []) if (typeof r.output === 'string') delete r.output;
    console.log(`EVIDENCE_FILE ${file} ${JSON.stringify(data)}`);
  }
}
