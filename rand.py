from pwn import *

r = ssh(user = 'random', host='pwnable.kr', port=2222, password='guest')
p = r.process(executable= './random')
p.sendline('3039230856')
print(p.recvall())