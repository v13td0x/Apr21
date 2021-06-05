from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

exe = './fluff32'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

data_section = 0x0804a018
pop_ebp = 0x080485bb
long_pext = 0x08048543
'''
mov     eax, ebp
mov     ebx, 0xb0bababa
pext    edx, ebx, eax
mov     eax, 0xdeadbeef
ret
'''
xchg_Pecx_dl = 0x08048555
bswap_ecx = 0x08048559
print_file  = 0x80483d0
# Start program
io = start()

payload = flat({
    offset: [

    ]
})

write('payload', payload)

io.sendlineafter('', payload)

io.interactive()

# flag = io.recv()
# success(flag)