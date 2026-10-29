"""Matrix-free exact EDP and best-trail, any m. Round on difference vector v over 2^(3m) states:
 S-layer step: Kronecker of the 8x8 DP table per S-box axis (sum for EDP, max-product for trail), then permute by L (state index a -> L(a)).
Same quantities as clus2.py. Index layout: S-box i = bits 3i..3i+2 (little-endian), so axis for sbox i is (m-1-i) in C-order reshape."""
import numpy as np,sys,time
from clus import layer,DP
def step(v,m,Ltab,mode):
    sh=(8,)*m;t=v.reshape(sh)
    for ax in range(m):
        if mode=="sum":
            t=np.moveaxis(np.tensordot(DP,t,axes=([0],[ax])),0,ax)   # new[b]=sum_a DP[a,b] t[a]
        else:
            tm=np.moveaxis(t,ax,0)                                    # [a, ...]
            new=(DP[:,:,None]*tm.reshape(8,1,-1)).max(axis=0)         # max_a DP[a,b]*t[a]
            t=np.moveaxis(new.reshape((8,)+tm.shape[1:]),0,ax)
    w=t.reshape(-1);out=np.zeros_like(w);out[Ltab]=w   # state after S-layer c -> L(c)? see below
    return out
def run_source(a,m,Linv_tab_unused,Ltab,r,mode):
    N=1<<(3*m);v=np.zeros(N);v[a]=1;res=[]
    for _ in range(r):
        v=step(v,m,Ltab,mode);res.append(v)
    return res
if __name__=="__main__":
    m=int(sys.argv[1]);kind=sys.argv[2];rmax=int(sys.argv[3]);seed=int(sys.argv[4]);srcmode=sys.argv[5] if len(sys.argv)>5 else "all"
    Lt=layer(m,kind,seed);N=1<<(3*m)
    # layout: reshape index (a = sum a_i 8^i) is C-order with axis0 = highest sbox; remap so axis k <-> sbox m-1-k
    srcs=range(1,N) if srcmode=="all" else [int(x) for x in srcmode.split(",")]
    t0=time.time();E=np.zeros(rmax);T=np.zeros(rmax)
    for a in srcs:
        e=run_source(a,m,None,Lt,rmax,"sum");t=run_source(a,m,None,Lt,rmax,"max")
        for r in range(rmax):
            E[r]=max(E[r],e[r][1:].max() if a==0 else e[r].max());T[r]=max(T[r],t[r].max())
    fl=1/(N-1)
    for r in range(rmax):print("%s s%d m=%d r=%d maxEDP=%.3e maxTrail=%.3e floor=%.3e"%(kind,seed,m,r+1,E[r],T[r],fl))
    print("time %.1fs"%(time.time()-t0))
