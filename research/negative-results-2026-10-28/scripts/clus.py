"""Trail-clustering measurement on a small key-alternating SPN. Research toy, not a cipher proposal.
State: m 3-bit S-boxes (S = x^3 over GF(8), bijective APN, DP=1/4 on nonzero rows). Round = key XOR, S-layer, linear layer L.
Independent uniform round keys => key-averaged EDP(a->b) over r rounds = (M^r)[a,b] with M[a,b]=prod_i DP_S(a_i -> (L^-1 b)_i) (exact; validated below by brute force).
Reports per r: max_{a!=0,b} EDP, max single-trail probability (sampled sources), ratio EDP(a,b)/trail(a,b) max over sampled pairs."""
import numpy as np, itertools, random, sys
def gf8mul(a,b):
    r=0
    for _ in range(3):
        if b&1:r^=a
        b>>=1;a<<=1
        if a&8:a^=0b1011
    return r
S=[gf8mul(gf8mul(x,x),x) for x in range(8)]
assert sorted(S)==list(range(8))
DP=np.zeros((8,8))
for a in range(8):
    for x in range(8): DP[a,S[x]^S[x^a]]+=1/8
def layer(m,kind,seed=0):
    n=3*m
    if kind=="bitperm":
        p=list(range(n));random.Random(seed).shuffle(p)
        f=lambda x:sum(((x>>i)&1)<<p[i] for i in range(n))
    else:  # random invertible GF(2) matrix
        rnd=random.Random(seed)
        while True:
            rows=[rnd.randrange(1,1<<n) for _ in range(n)]
            # rank check
            r=rows[:];rk=0
            for bit in range(n):
                piv=next((i for i in range(rk,n) if r[i]>>bit&1),None)
                if piv is None:continue
                r[rk],r[piv]=r[piv],r[rk]
                for i in range(n):
                    if i!=rk and r[i]>>bit&1:r[i]^=r[rk]
                rk+=1
            if rk==n:break
        f=lambda x:sum((bin(rows[i]&x).count('1')&1)<<i for i in range(n))
    tab=[f(x) for x in range(1<<n)]
    assert len(set(tab))==1<<n
    return tab
def Mmat(m,Ltab):
    n=3*m;N=1<<n;inv=[0]*N
    for x,y in enumerate(Ltab):inv[y]=x
    M=np.zeros((N,N),dtype=np.float64)
    for a in range(N):
        ai=[(a>>(3*i))&7 for i in range(m)]
        for b in range(N):
            c=inv[b];p=1.0
            for i in range(m):
                p*=DP[ai[i],(c>>(3*i))&7]
                if p==0:break
            M[a,b]=p
    return M
def validate():
    m=2;n=6;N=64;Lt=layer(m,"rand",1);M=Mmat(m,Lt);P=M@M
    def rnd(x,k):
        y=x^k;z=0
        for i in range(m):z|=S[(y>>(3*i))&7]<<(3*i)
        return Lt[z]
    # brute force key average, 2 rounds
    cnt=np.zeros((N,N))
    for k1 in range(N):
        for k2 in range(N):
            out=[rnd(rnd(x,k1),k2) for x in range(N)]
            for a in range(1,N):
                for x in range(N):
                    cnt[a,out[x]^out[x^a]]+=1
    est=cnt/(N*N*N)
    err=np.abs(est[1:]-P[1:]).max()
    print("validation m=2 r=2: max |bruteforce keyaveraged - M^2| =",err)
    return err
def trailmax(M,a,r):
    N=M.shape[0];v=np.zeros(N);v[a]=1
    for _ in range(r):
        v=(v[:,None]*M).max(axis=0)
    return v
if __name__=="__main__":
    if sys.argv[1]=="val":validate();sys.exit()
    m=int(sys.argv[1]);kind=sys.argv[2];rmax=int(sys.argv[3]);seed=int(sys.argv[4]) if len(sys.argv)>4 else 0
    Lt=layer(m,kind,seed);M=Mmat(m,Lt);N=M.shape[0]
    rnd=random.Random(5);srcs=[1,2,4,8,9]+[rnd.randrange(1,N) for _ in range(40)]
    P=np.eye(N)
    for r in range(1,rmax+1):
        P=P@M
        edp=P[1:].max()
        worst=0;argm=None;mt=0
        for a in srcs:
            t=trailmax(M,a,r)
            mt=max(mt,t.max())
            mask=t>0
            ratio=(P[a][mask]/t[mask]).max()
            if ratio>worst:worst=ratio;argm=a
        print("m=%d %s seed=%d r=%d: maxEDP=%.3e  maxSingleTrail(sampled src)=%.3e  max EDP/trail over sampled pairs=%.2f (src %s)"%(m,kind,seed,r,edp,mt,worst,argm),flush=True)
