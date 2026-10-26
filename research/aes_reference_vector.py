"""Optional independent fixture generator. Requires Python cryptography; not needed by cargo tests."""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
k=bytes([3])*32;n=bytes([7])*12;p=b'Obsidian AES independent vector'
h=b'OBS1'+bytes([2,0,0,0])+n
print((h+AESGCM(k).encrypt(n,p,h)).hex())
