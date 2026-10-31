// Regression: encrypt/decrypt must not leave consumed secret input bytes in
// wasm memory. The glue passes copies of key/plaintext into wasm memory and
// the wasm side takes ownership (Vec::from_raw_parts) and frees them inside
// the call; secret inputs must be wiped while owned, before deallocation.
// Input-block addresses are predicted with guard-separated allocator probes
// and cross-checked with a canary input (nonce/envelope) that is freed
// without wiping by design. Synthetic markers only; this is input-copy
// hygiene, not all-memory erasure.
const assert = require('node:assert/strict');
const { chromium } = require('playwright-core');
(async () => {
  const base = process.argv[2] || 'http://127.0.0.1:8183';
  const browser = await chromium.launch({ executablePath: '/usr/bin/google-chrome' });
  const page = await browser.newPage();
  await page.goto(base);
  const r = await page.evaluate(async () => {
    const m = await import('./pkg/obsidian_research.js');
    const w = await m.default();
    const malloc = w.__wbindgen_malloc.bind(w), free = w.__wbindgen_free.bind(w);
    const keyMarker = new Uint8Array(32); for (let i = 0; i < 32; i++) keyMarker[i] = 201 + i;
    const nonceMarker = new Uint8Array(24); for (let i = 0; i < 24; i++) nonceMarker[i] = 150 + i;
    const plainMarker = new TextEncoder().encode('SYNTHETIC-INPUT-PLAINTEXT-64B-MARKER-9f27c441-aaaa-bbbb-cccc-ddd');
    if (plainMarker.length !== 64) throw Error('marker length');
    const keySuffix = keyMarker.subarray(8), keySuffix4 = keyMarker.subarray(4), plainSuffix = plainMarker.subarray(8);
    const hex = (u) => Array.from(u, b => b.toString(16).padStart(2, '0')).join('');
    const zero = (u) => u.every(b => b === 0);
    const eq = (u, ref) => u.length === ref.length && u.every((b, i) => b === ref[i]);
    const view = (ptr, len) => new Uint8Array(w.memory.buffer, ptr, len);
    function scan(needle) { const hay = new Uint8Array(w.memory.buffer); let hits = 0; outer: for (let i = 0; i + needle.length <= hay.length; i++) { for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer; hits++; } return hits; }
    // seed one freed chunk per size class, separated by live guards so the
    // allocator cannot coalesce them; the next same-size malloc reuses it (LIFO)
    function seeded() {
      const a = malloc(32, 1), g1 = malloc(8, 1), b = malloc(64, 1), g2 = malloc(8, 1), c = malloc(24, 1), g3 = malloc(8, 1), d = malloc(136, 1), g4 = malloc(8, 1);
      free(a, 32, 1); free(b, 64, 1); free(c, 24, 1); free(d, 136, 1);
      return { key: a, plain: b, nonce: c, env: d, guards: [g1, g2, g3, g4] };
    }
    function unguard(g) { free(g[0], 8, 1); free(g[1], 8, 1); free(g[2], 8, 1); free(g[3], 8, 1); }
    const out = {};
    // encrypt: glue mallocs key(32), nonce(24), plain(64) in order
    let s = seeded();
    const key = keyMarker.slice(), input = plainMarker.slice();
    const ct = m.encrypt(0, key, nonceMarker.slice(), input);
    out.encryptKeySuffixZero = zero(view(s.key + 8, 24)); out.encryptKeySuffixHex = hex(view(s.key + 8, 24)).slice(0, 32);
    out.encryptPlainSuffixZero = zero(view(s.plain + 8, 56)); out.encryptPlainSuffixHex = hex(view(s.plain + 8, 56)).slice(0, 32);
    out.encryptKeyPrefix8Hex = hex(view(s.key, 8));
    out.encryptPlainPrefix8Hex = hex(view(s.plain, 8));
    out.encryptNonceCanaryRetained = eq(view(s.nonce + 8, 16), nonceMarker.subarray(8, 24));
    const pa = malloc(32, 1); out.encryptKeyBlockFreed = (pa === s.key); free(pa, 32, 1);
    const pb = malloc(64, 1); out.encryptPlainBlockFreed = (pb === s.plain); free(pb, 64, 1);
    unguard(s.guards);
    out.encryptKeySuffixHits = scan(keySuffix); out.encryptPlainSuffixHits = scan(plainSuffix); out.keySuffix4Hits = scan(keySuffix4);
    // reuse probe: a second encrypt after the frees must still roundtrip
    const key2 = new Uint8Array(32); for (let i = 0; i < 32; i++) key2[i] = 101 + i;
    const back2 = m.decrypt(key2, m.encrypt(0, key2, new Uint8Array(24), plainMarker.slice()));
    out.reuseRoundtrip = eq(back2, plainMarker);
    // decrypt: glue mallocs key(32), envelope(ct.length) in order
    s = seeded();
    const back1 = m.decrypt(keyMarker.slice(), ct);
    out.decryptKeySuffixZero = zero(view(s.key + 8, 24)); out.decryptKeySuffixHex = hex(view(s.key + 8, 24)).slice(0, 32);
    out.decryptKeyPrefix8Hex = hex(view(s.key, 8));
    out.decryptEnvCanaryRetained = ct.length >= 24 && eq(view(s.env + 8, 16), ct.subarray(8, 24));
    const pa2 = malloc(32, 1); out.decryptKeyBlockFreed = (pa2 === s.key); free(pa2, 32, 1);
    unguard(s.guards);
    out.roundtrip = eq(back1, plainMarker);
    out.decryptKeySuffixHits = scan(keySuffix);
    // tamper error path
    const env = m.encrypt(0, keyMarker.slice(), new Uint8Array(24), plainMarker.slice());
    env[env.length - 1] ^= 1;
    s = seeded();
    let threw = false;
    try { m.decrypt(keyMarker.slice(), env); } catch (e) { threw = true; }
    out.errorThrew = threw;
    out.errorKeySuffixZero = zero(view(s.key + 8, 24)); out.errorKeySuffixHex = hex(view(s.key + 8, 24)).slice(0, 32);
    out.errorKeyPrefix8Hex = hex(view(s.key, 8));
    unguard(s.guards);
    out.errorKeySuffixHits = scan(keySuffix); out.errorPlainSuffixHits = scan(plainSuffix);
    // allocator health after everything: 100 roundtrips
    let ok = true;
    for (let i = 0; i < 100; i++) { const k = new Uint8Array(32); k[0] = i & 0xff; const p = new Uint8Array(64); p[0] = i & 0xff; const o = m.decrypt(k, m.encrypt(0, k, new Uint8Array(24), p)); if (o.length !== 64 || o[0] !== (i & 0xff)) { ok = false; break; } }
    out.allocatorHealthy100 = ok;
    return out;
  });
  await browser.close();
  console.log(JSON.stringify(r, null, 2));
  assert(r.roundtrip, 'roundtrip failed'); assert(r.reuseRoundtrip, 'post-free reuse roundtrip failed');
  assert(r.errorThrew, 'tampered envelope accepted'); assert(r.allocatorHealthy100, 'allocator unhealthy after wipes');
  assert(r.encryptNonceCanaryRetained, 'nonce canary missing; address prediction unreliable');
  assert(r.decryptEnvCanaryRetained, 'envelope canary missing; address prediction unreliable');
  // freed-inside-call evidence: the allocator overwrites the first 8 bytes of
  // a released block with freelist metadata, so no target block may still
  // carry its marker prefix
  function hex8(u) { return Array.from(u.subarray(0, 8), b => b.toString(16).padStart(2, '0')).join(''); }
  const keyPrefix = 'c9cacbcccdcecfd0', plainPrefix = '53594e5448455449';
  assert(r.encryptKeyPrefix8Hex !== keyPrefix && r.decryptKeyPrefix8Hex !== keyPrefix && r.errorKeyPrefix8Hex !== keyPrefix, 'key block prefix not clobbered; block not freed: ' + JSON.stringify(r));
  assert(r.encryptPlainPrefix8Hex !== plainPrefix, 'plain block prefix not clobbered; block not freed: ' + JSON.stringify(r));
  // direct wipe proof on the 64B plain block: its live guard neighbors keep
  // it from coalescing until after inspection, so post-free allocator writes
  // stay within its 8-byte prefix and its 56B suffix must be zeroed. For key
  // blocks, the glue frees the returned output block after the call and it
  // can coalesce with the freed key block, writing allocator metadata past
  // the 8-byte prefix, so the whole-memory marker scans below are the key
  // assertion and the region hexes are evidence. The safety argument itself
  // rests on the Rust ownership chain, not on these observations.
  assert(r.encryptPlainSuffixZero === true, 'consumed plain suffix not wiped: ' + JSON.stringify(r));
  const hits = ['encryptKeySuffixHits', 'encryptPlainSuffixHits', 'keySuffix4Hits', 'decryptKeySuffixHits', 'errorKeySuffixHits', 'errorPlainSuffixHits'];
  assert(hits.every(k => r[k] === 0), 'retained input suffix bytes: ' + JSON.stringify(r));
})().catch(e => { console.error(e); process.exit(1); });
