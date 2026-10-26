"""Independent stdlib R1 vector, fixed nonsecret inputs. Run python3 research/reference_vector.py."""
import hmac, hashlib
mac=lambda k,m:hmac.new(k,m,hashlib.sha256).digest()
k=bytes([3])*32;n=bytes([7])*24;p=b'Obsidian reference vector'
prk=mac(n,k); info=b'Obsidian/R1/stream+auth'
t1=mac(prk,info+b'\x01'); t2=mac(prk,t1+info+b'\x02'); keys=t1+t2
header=b'OBS1'+bytes(4)+n
stream=mac(keys[:32],b'Obsidian/R1/block'+n+bytes(8))
c=bytes(a^b for a,b in zip(p,stream));out=header+c+mac(keys[32:],header+c)
print(out.hex())
