"""clus3 with an alternate 3-bit S-box (argv: SBOX as 8 comma-separated values first). Same exact all-source method."""
import sys,numpy as np
sb=[int(x) for x in sys.argv[1].split(',')];assert sorted(sb)==list(range(8))
import clus
D=np.zeros((8,8))
for a in range(8):
    for x in range(8):D[a,sb[x]^sb[x^a]]+=1/8
clus.DP[:]=D
print("sbox",sb,"maxDP(nonzero a)=",D[1:].max())
import clus3
clus3.DP=D
sys.argv=[sys.argv[0]]+sys.argv[2:]
exec(open('clus3.py').read().split('if __name__=="__main__":')[1].replace('\n    ','\n'),{**clus3.__dict__,'__name__':'x'})
