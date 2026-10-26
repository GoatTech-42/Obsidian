// Obsidian R1 fuzz + independent AES KAT, round 1 (reviewer harness, v3 deployed wasm).
// Usage: PKG=<path to web/pkg dir> node h2-v3.mjs
import fs from 'fs';
const PKG=process.env.PKG||new URL('./pkg',import.meta.url).pathname;
const mod=await import(PKG+'/obsidian_research.js');
await mod.default(fs.readFileSync(PKG+'/obsidian_research_bg.wasm'));
const {encrypt,decrypt}=mod;
let fails=0;const rec=(n,ok,info='')=>{console.log((ok?'PASS':'FAIL')+': '+n+(info?' ('+info+')':''));if(!ok)fails++;};
const key=await crypto.subtle.importKey('raw',new Uint8Array(32).fill(3),'AES-GCM',false,['encrypt']);
const header=new Uint8Array([0x4f,0x42,0x53,0x31,2,0,0,0,...Array(12).fill(7)]);
const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:new Uint8Array(12).fill(7),additionalData:header},key,new TextEncoder().encode('Obsidian AES independent vector')));
const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
const mine=hex(header)+hex(ct);
const claimed='4f425331020000000707070707070707070707075b4fb7ca7001fbcb1adf3eb0077fca912b8e06eb9fac856b6aaeb673d732f4a97081612611d08eb191d0cf2f3758d9';
rec('AES-GCM fixture independently reproduced via WebCrypto',mine===claimed);
// random fuzz: half with CORRECT magic OBS1 (0x31) to exercise deep-parse paths
let panics=0,accepted=0;
const keyB=new Uint8Array(32).fill(9);
for(let i=0;i<4000;i++){
  const len=Math.floor(Math.random()*80);const b=new Uint8Array(len);crypto.getRandomValues(b);
  if(len>=4&&i%2===0){b[0]=0x4f;b[1]=0x42;b[2]=0x53;b[3]=0x31;} // 'OBS1'
  try{decrypt(keyB,b);accepted++;}catch(x){const m=String(x);if(/panic|unreachable|out of bounds|index/i.test(m)){panics++;console.log('PANIC len='+len+': '+m);}}
}
rec('4000-case random fuzz (half valid-magic)',accepted===0&&panics===0,'accepted='+accepted+' panics='+panics);
const n24=new Uint8Array(24).fill(5);const e=encrypt(0,keyB,n24,new TextEncoder().encode('structured fuzz target'));
let acc2=0,pan2=0;
for(let i=0;i<2000;i++){const b=e.slice();b[Math.floor(Math.random()*b.length)]^=1+Math.floor(Math.random()*255);
  try{decrypt(keyB,b);acc2++;}catch(x){const m=String(x);if(/panic|unreachable|out of bounds|index/i.test(m))pan2++;}}
rec('2000-case structured corruption',acc2===0&&pan2===0,'accepted='+acc2+' panics='+pan2);
process.exit(fails?1:0);
