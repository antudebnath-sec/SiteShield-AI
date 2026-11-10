import { readFileSync } from 'node:fs';
import { urlFeatures } from '../src/features.js';
const urls = readFileSync(process.argv[2], 'utf8').split('\n').map((s) => s.trim()).filter(Boolean);
const out = {};
for (const u of urls) { const r = urlFeatures(u); out[u] = r && r.f; }
console.log(JSON.stringify(out, null, 1));
