// Repeated wasm benchmark: the same jobs, sizes, iterations and CSV columns as
// examples/bench_runs.rs, run through the wasm-bindgen glue in Node.
// Usage: node scripts/bench_wasm.mjs <dir with obsidian_research.js, built with
//        wasm-bindgen --target nodejs> [runs]
// Rows are only comparable with the native row of the same mode, op and size;
// never rank different jobs against each other. The wasm path also copies the
// key, nonce, payload and result across the JS/wasm boundary on every call.
import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { resolve } from "node:path";

const dir = process.argv[2];
if (!dir) { console.error("usage: node scripts/bench_wasm.mjs <wasm-bindgen nodejs dir> [runs]"); process.exit(64); }
const runs = Math.max(1, parseInt(process.argv[3] ?? "9", 10) || 9);
const { encrypt, decrypt } = createRequire(import.meta.url)(resolve(dir, "obsidian_research.js"));

const median = (v) => {
  const s = [...v].sort((a, b) => a - b), n = s.length;
  return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
};
const nonceLen = (mode) => (mode === 2 ? 12 : 24);
const key = new Uint8Array(32).fill(9);

// Same fixed test envelopes as examples/envelope_digest.rs.
for (let mode = 0; mode <= 2; mode++) {
  const env = encrypt(mode, key, new Uint8Array(nonceLen(mode)).fill(3), new Uint8Array(64).fill(42));
  console.log(`digest,${mode},${createHash("sha256").update(env).digest("hex")}`);
}

console.log("mode,op,bytes,runs,iterations,median_mib_s,min_mib_s,max_mib_s,spread_pct");
let sink = 0;
for (const size of [64, 4096, 1048576]) {
  for (let mode = 0; mode <= 2; mode++) {
    const iterations = size === 1048576 ? 12 : 200;
    const data = new Uint8Array(size).fill(42);
    const n = nonceLen(mode);
    const envelope = encrypt(mode, key, new Uint8Array(n).fill(3), data);
    const mib = (size * iterations) / 1048576;
    for (const op of ["seal", "open"]) {
      const rates = [];
      for (let r = 0; r < runs; r++) {
        const start = process.hrtime.bigint();
        for (let i = 0; i < iterations; i++) {
          if (op === "seal") {
            const nonce = new Uint8Array(n);
            new DataView(nonce.buffer).setBigUint64(0, BigInt(i));
            sink += encrypt(mode, key, nonce, data).length;
          } else {
            sink += decrypt(key, envelope).length;
          }
        }
        rates.push(mib / (Number(process.hrtime.bigint() - start) / 1e9));
      }
      const min = Math.min(...rates), max = Math.max(...rates), med = median(rates);
      console.log(`${mode},${op},${size},${runs},${iterations},${med.toFixed(3)},${min.toFixed(3)},${max.toFixed(3)},${(((max - min) / med) * 100).toFixed(1)}`);
    }
  }
}
if (sink === 0) console.error("unexpected: nothing was processed");
