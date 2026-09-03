/**
 * Export a validated document for the round-trip harness.
 *
 * Deliberately produced by the SAME code paths the page uses — buildDefaultDocument
 * then runPipeline — so what Python receives is what a visitor would get from
 * Copy JSON, not a fixture assembled to be easy to verify.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { buildDefaultDocument } from '../src/defaults.js';
import { runPipeline } from '../src/pipeline.js';

const root = new URL('..', import.meta.url).pathname;
const document = await buildDefaultDocument();
const result = await runPipeline({ document: JSON.parse(JSON.stringify(document)) });

if (result.verdict !== 'PASS') {
  console.error(`refusing to export a document this playground itself denies: ${result.error_code}`);
  process.exit(1);
}

// The export carries the pipeline result PLUS the fields Python needs: private
// keys, the policy envelope and the Registry's version in force, which the
// display-oriented result does not repeat.
const out = {
  ...result,
  chain: document.chain,
  authorities: document.authorities,
  policy: document.policy,
  current_policy_version: document.current_policy_version,
  crl: document.crl,
};
mkdirSync(root + 'dist', { recursive: true });
writeFileSync(root + 'dist/roundtrip-export.json', JSON.stringify(out, null, 2));
console.log(`exported a PASSING chain — ${result.walk.length} steps, ${result.stages.length} stages`);
