Tamu CTF 21

IDA:

```c
  len_text = strlen(argv[1]);
  ptr = (char *)malloc(len_text);
  srand(0x1337u);
  for ( i = 0; i < len_text; ++i )
  {
    v3 = argv[1][(i + 15) % len_text];
    ptr[i] = (rand() ^ rand() ^ v3) % 256;
    // neu rand1 va rand2 la byte va v3 da la byte roi thi ptr[i] chac chan la byte
  }
  printf("%s", ptr);
  free(ptr);
  return 0;
```

Ghidra

```c
  sVar2 = strlen(*(char **)(param_2 + 8));
  len = (int)sVar2;
  __ptr = malloc((long)len);
  srand(0x1337);
  pos = 0;
  while (pos < len) {
    bVar1 = *(byte *)((long)((pos + 0xf) % len) + *(long *)(param_2 + 8));
    // bVar1 = argv[1][(pos + 0xf) % len]
    rand1 = rand();
    rand2 = rand();
    *(byte *)((long)__ptr + (long)pos) = bVar1 ^ (byte)rand1 ^ (byte)rand2;
    // ptr[pos] = bVar1 ^ (byte)rand1 ^ (byte)rand2
    pos = pos + 1;
  }
  printf("%s",__ptr);
  free(__ptr);
  return 0;
```

Solve:

```python
import random
from ctypes import CDLL

libc = CDLL("libc.so.6") 
libc.srand(0x1337)
f=open('flag.enc','rb')
X=[]
while(True):
    c=f.read(1)
    if not c:
        break
    b = int.from_bytes(c, byteorder='big')
    M=hex(b^libc.rand()^libc.rand()).strip()[-2:]
    X.append(chr(int(M,16)))
print(''.join(X))
```

c2:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void main() {
    int r;

    srand(0x1337);
    for (int i; i<68; i++) {
        r = rand();
        printf("%d\n", r & 0xff);
        // (BYTE)rand = r % 256
    }
}
```

```python
r = [37, 46, 34, 215, 193, 114, 215, 110, 179, 42, 163, 241, 248, 234, 240,
    176, 87, 213, 232, 226, 11, 127, 8, 77, 207, 216, 0, 232, 251, 141, 107,
    33, 187, 141, 248, 124, 255, 208, 234, 178, 250, 141, 163, 242, 119, 147,
    163, 207, 105, 139, 177, 116, 10, 186, 193, 217, 146, 194, 194, 141, 79,
    45, 174, 10, 186, 167, 134, 185]
# result of code segment above
with open('flag.enc', 'rb') as f:
    enc = f.read()

l = len(enc)
flag = [''] * l
for i in range(l):
    code = r[i*2] ^ r[i*2+1] ^ ord(enc[i])
    flag[(i + 15) % l] = chr(code)
flag = ''.join(flag)
print flag
```

