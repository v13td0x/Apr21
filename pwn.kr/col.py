from pwn import *

r = ssh(user = 'col', host = 'pwnable.kr', port = 2222, password = 'guest')
#_______________________________________1__________________________________
payload = p32(0x6c5cecc) + 4 * p32(0x6c5cec8)
p = r.process(executable= './col', argv= ['col', payload])
print(p.recv())
#_______________________________________2__________________________________
payload = b'\xc8\xce\xc5\x06'*4 + b'\xcc\xce\xc5\x06'
p = r.process(['./col', payload])
print(p.recvall())