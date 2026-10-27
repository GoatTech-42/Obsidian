"""Wipe the wasm-bindgen 0.2.105 decrypt return allocation before freeing it.

Run after wasm-bindgen. Fail closed if the generated shape changes.
This does not erase JS/DOM strings or make browser memory secret.
"""
from pathlib import Path

path = Path(__file__).resolve().parents[1] / "web/pkg/obsidian_research.js"
source = path.read_text()
old = """    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;"""
new = """    // Clear this returned plaintext allocation, not all browser memory.
    const plaintextView = getArrayU8FromWasm0(ret[0], ret[1]);
    try {
        return plaintextView.slice();
    } finally {
        plaintextView.fill(0);
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }"""
if source.count(old) != 1:
    raise SystemExit("Unexpected decrypt glue shape; review before rebuilding.")
path.write_text(source.replace(old, new))
