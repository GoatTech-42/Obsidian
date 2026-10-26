import hmac,hashlib
def hkdf_expand(salt,ikm,info,L):
    prk=hmac.new(salt,ikm,hashlib.sha256).digest()
    out=b'';t=b'';c=1
    while len(out)<L:
        t=hmac.new(prk,t+info+bytes([c]),hashlib.sha256).digest();out+=t;c+=1
    return out[:L]
key=bytes([3])*32;nonce=bytes([7])*24
k=hkdf_expand(nonce,key,b"Obsidian/R1/stream+auth",64)
ks,km=k[:32],k[32:]
plain=b"Obsidian reference vector"
header=b"OBS1"+bytes([0,0,0,0])+nonce
body=b''
for i in range(0,len(plain),32):
    blk=plain[i:i+32]
    m=hmac.new(ks,b"Obsidian/R1/block",hashlib.sha256);m.update(nonce);m.update((i//32).to_bytes(8,'big'))
    s=m.digest();body+=bytes(a^b for a,b in zip(blk,s))
m=hmac.new(km,header,hashlib.sha256);m.update(body);body+=m.digest()
got=(header+body).hex()
expected="4f42533100000000070707070707070707070707070707070707070707070707d880601f3d32722cc6f06dc3c13af599add87afa8e8f527bde2fab39d612a020cdf1e4ed3bc5f813af8a2cc068c82c01d3c727b56178403799"
print("PASS: independent R1 KAT matches" if got==expected else "FAIL: "+got)
