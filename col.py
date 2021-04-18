from pwn import *

payload = p32(0x6c5cecc) + 4 * p32(0x6c5cec8)
r = ssh(user = 'col', host = 'pwnable.kr', port = 2222, password = 'guest')
p = r.process(executable= './col', argv= ['col', payload])
print(p.recv())
