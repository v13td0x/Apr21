HackPack CTF 2021

> Arch:     amd64-64-little
> RELRO:    Partial RELRO
> Stack:    `Canary found`
> NX:       NX disabled
> PIE:      No PIE (0x400000)
> RWX:      Has RWX segments

```python
-0000000000001010 data            db 4096 dup(?)
-0000000000000010                 db ? ; undefined
-000000000000000F                 db ? ; undefined
-000000000000000E                 db ? ; undefined
-000000000000000D                 db ? ; undefined
-000000000000000C                 db ? ; undefined
-000000000000000B                 db ? ; undefined
-000000000000000A                 db ? ; undefined
-0000000000000009                 db ? ; undefined
-0000000000000008 var_8           dq ?
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

Bai nay can bypass canary

> 1. Read the saved rbp.
>
> 2. Calculate from rbp and rewrite the return address on the stack.
> 3. Put the shellcode on the stack (because it's RWX)



