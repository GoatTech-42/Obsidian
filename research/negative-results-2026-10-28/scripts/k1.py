"""K1: research toy, NOT a security proposal. Keyed Feistel on 2n-bit block, halves in GF(2^n), n odd.
Round i: (L,R) -> (R, L xor (R xor k_i)^3), cube in GF(2^n). Independent round keys k_i (n bits each) = the
setting of Nyberg-Knudsen hypotheses. 'Schedule' variant: k_i = derived from master via SHA-256 (implementable, hypotheses NOT satisfied).
Bijective F (x^3 on odd n), APN: pF = 2^(1-n)."""
import hashlib, random, sys
import numpy as np
POLY={5:0b100101,7:0b10000011}
def mul(a,b,n):
    p=POLY[n];r=0
    while b:
        if b&1:r^=a
        b>>=1;a<<=1
        if a>>n&1:a^=p
    return r
class K1:
    def __init__(s,n,keys):
        s.n=n;s.keys=list(keys);s.cube=[mul(mul(x,x,n),x,n) for x in range(1<<n)]
    def enc(s,L,R):
        for k in s.keys: L,R=R,L^s.cube[R^k]
        return L,R
    def dec(s,L,R):
        for k in reversed(s.keys): L,R=R^s.cube[L^k],L
        return L,R
def schedule(master:bytes,n,r):
    return [hashlib.sha256(master+bytes([i])).digest()[0]&((1<<n)-1) for i in range(r)]
def tables(n,keys):
    N=1<<n;cube=np.array([mul(mul(x,x,n),x,n) for x in range(N)])
    x=np.arange(N*N);L=x>>n;R=x&(N-1)
    for k in keys: L,R=R,L^cube[R^k]
    return (L<<n)|R
def maxdp(out,n):
    M=len(out);x=np.arange(M);best=0;cnt=None
    return out,x
def diffmax_and_avgcount(outs,n):
    """outs: list of output permutations (one per key sample). Returns (avg over keys of max over diffs of fixed-key DP,
    max over diffs of key-averaged DP)."""
    M=len(outs[0]);x=np.arange(M);fixed=[];acc=np.zeros((M,M),dtype=np.float32) if M<=1024 else None
    for out in outs:
        mx=0
        for a in range(1,M):
            d=out^out[x^a]
            c=np.bincount(d,minlength=M)
            mx=max(mx,c.max())
            acc[a]+=c
        fixed.append(mx/M)
    return float(np.mean(fixed)),float(acc.max()/(M*len(outs)))
if __name__=="__main__":
    n=int(sys.argv[1]);samples=int(sys.argv[2]);maxr=int(sys.argv[3])
    rnd=random.Random(7)
    # correctness: inverse + fixed vector
    k=K1(n,[rnd.randrange(1<<n) for _ in range(6)])
    assert all(k.dec(*k.enc(L,R))==(L,R) for L in range(1<<n) for R in range(1<<n))
    print("inverse ok n=%d; vector keys=%s enc(1,2)=%s"%(n,k.keys,k.enc(1,2)))
    print("pF=%g, KN keyed bound 2pF^2=%g (needs independent uniform keys, r>=3)"%(2.0**(1-n),2*4.0**(1-n)))
    for r in range(2,maxr+1):
        outs=[tables(n,[rnd.randrange(1<<n) for _ in range(r)]) for _ in range(samples)]
        f,a=diffmax_and_avgcount(outs,n)
        print("r=%d indep-keys: mean fixed-key maxDP=%.5f  max key-averaged DP (sampled %d keys)=%.5f"%(r,f,samples,a),flush=True)
