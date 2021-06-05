Also noted in the article is that it’s possible to use pointers for the `_fini` function, located at `&_DYNAMIC`. That’s just what we need for `r12`, as we’ll zero `rbx` - `call [_fini+0*8]`

```
pwndbg> x/10gx &_DYNAMIC
0x600e00:       0x0000000000000001      0x0000000000000001
0x600e10:       0x0000000000000001      0x0000000000000038
0x600e20:       0x000000000000001d      0x0000000000000078
0x600e30:       0x000000000000000c      0x00000000004004d0
0x600e40:       0x000000000000000d      0x00000000004006b4  #--> call [r12]
pwndbg> disassemble  0x004006b4
Dump of assembler code for function _fini:
   0x00000000004006b4 <+0>:     sub    rsp,0x8
   0x00000000004006b8 <+4>:     add    rsp,0x8
   0x00000000004006bc <+8>:     ret
```

chon `_fini` function vi ham nay cha lam gi ma lai ret tro ve gadget cu

