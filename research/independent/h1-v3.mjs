// Obsidian R1 attack suite, round 1 (reviewer harness, v3 deployed wasm).
// Usage: PKG=<path to web/pkg dir> node h1-v3.mjs   (PKG defaults to ./pkg)
import fs from 'fs';
const PKG=process.env.PKG||new URL('./pkg',import.meta.url).pathname;
const mod=await import(PKG+'/obsidian_research.js');
await mod.default(fs.readFileSync(PKG+'/obsidian_research_bg.wasm'));
const {encrypt,decrypt}=mod;
let fails=0;const rec=(n,ok,info='')=>{console.log((ok?'PASS':'FAIL')+': '+n+(info?' ('+info+')':''));if(!ok)fails++;};
const key=new Uint8Array(32).fill(3),n24=new Uint8Array(24).fill(7),n12=new Uint8Array(12).fill(7);
for(const [m,n] of [[0,n24],[1,n24],[2,n12]]){
  try{const e=encrypt(m,key,n,new TextEncoder().encode('ferret redemption arc'));
      rec('roundtrip-mode'+m,new TextDecoder().decode(decrypt(key,e))==='ferret redemption arc');}
  catch(x){rec('roundtrip-mode'+m,false,String(x));}
}
// every-byte tamper + ALL truncations + extension; counters count every case
let accepted=0,total=0,panics=0;
for(const [m,n] of [[0,n24],[1,n24],[2,n12]]){
  const e=encrypt(m,key,n,new TextEncoder().encode('tamper target'));
  for(let i=0;i<e.length;i++){const b=e.slice();b[i]^=1;total++;try{decrypt(key,b);accepted++;}catch(x){if(/panic|unreachable|index/i.test(String(x)))panics++;}}
  for(let t=0;t<e.length;t++){total++;try{decrypt(key,e.slice(0,t));accepted++;}catch{}}
  total++;const e2=new Uint8Array(e.length+1);e2.set(e);try{decrypt(key,e2);accepted++;}catch{}
}
rec('every-byte tamper + every truncation + extension, all modes',accepted===0&&panics===0,total+' cases, accepted='+accepted+' panics='+panics);
// nonce-reuse recovery, ALL modes (stream-reuse property: c1^c2 = p1^p2 over the shared prefix)
for(const [m,n] of [[0,n24],[1,n24],[2,n12]]){
  const p1=new TextEncoder().encode('AAAA AAAA AAAA AA'),p2=new TextEncoder().encode('BBBB BBBB BBBB BB');
  const e1=encrypt(m,key,n,p1),e2=encrypt(m,key,n,p2);
  const off=8+n.length, tag=m===0?32:16;
  const c1=e1.slice(off,e1.length-tag),c2=e2.slice(off,e2.length-tag);
  const xok=c1.every((b,i)=>(b^c2[i])===(p1[i]^p2[i]));
  const rec2=c2.map((b,i)=>b^(c1[i]^p1[i]));
  rec('nonce-reuse recovery mode'+m+' (KNOWN limitation, reproduced)',xok&&rec2.every((b,i)=>b===p2[i]));
}
let fuzzPanics=0;
const samples=[[],[0],[1,2,3],[79,66,83,49],[79,66,83,49,0],[79,66,83,49,0,1,2,3],[79,66,83,49,9,0,0,0],
 [79,66,83,49,0,0,0,0],[79,66,83,49,1,0,0,0],[79,66,83,49,2,0,0,0],
 Array.from({length:40},(_,i)=>i),Array.from({length:39},()=>0),Array.from({length:33},()=>7),
 [79,66,83,49,0,0,0,0,...Array(24).fill(7)],[79,66,83,49,0,0,0,0,...Array(24).fill(7),...Array(31).fill(1)]];
for(const s of samples){try{decrypt(key,new Uint8Array(s));}catch(x){if(/panic|unreachable|index|slice/i.test(String(x)))fuzzPanics++;}}
rec('malformed opens: no panics',fuzzPanics===0,samples.length+' probes');
try{encrypt(0,key,n24,new Uint8Array(1048576));rec('seal MAX ok',true);}catch(x){rec('seal MAX ok',false,String(x));}
try{encrypt(0,key,n24,new Uint8Array(1048577));rec('seal MAX+1 TooLarge',false,'accepted');}catch(x){rec('seal MAX+1 TooLarge',/TooLarge/.test(String(x)),String(x));}
try{decrypt(key,encrypt(0,key,n24,new Uint8Array(0)));rec('empty plaintext roundtrip',true);}catch(x){rec('empty plaintext roundtrip',false,String(x));}
const e0=encrypt(0,key,n24,new TextEncoder().encode('x'));
let b=e0.slice();b[5]=1;try{decrypt(key,b);rec('reserved byte reject',false);}catch{rec('reserved byte reject',true);}
b=e0.slice();b[4]=3;try{decrypt(key,b);rec('bad mode reject',false);}catch{rec('bad mode reject',true);}
try{decrypt(new Uint8Array(32).fill(4),e0);rec('wrong key reject',false);}catch{rec('wrong key reject',true);}
process.exit(fails?1:0);
