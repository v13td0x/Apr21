pseudocode phase6

```c
puts("\nOh no... I lost the key to my string again :(");
dont_be_0 = 1;
s[0] = 0x40;
s[1] = 0x77;
s[2] = 0x23;
s[3] = 0x91;
s[4] = 0xB0;
s[5] = 0x72;
s[6] = 0x82;
s[7] = 0x77;
s[8] = 0x63;
s[9] = 0x31;
s[10] = 0xA2;
s[11] = 0x72;
s[12] = 0x21;
s[13] = 0xF2;
s[14] = 0x67;
s[15] = 0x82;
s[16] = 0x91;
s[17] = 0x77;
s[18] = 0x26;
s[19] = 0x91;
s[20] = 0;
s[21] = 0x33;
s[22] = 0x82;
s[23] = 0xC4;
input = (char *)calloc(0x29uLL, 1uLL);
getInput(6, a1, (unsigned int)"%s", (_DWORD)input, v1, v2);
for ( i = 0; i < strlen(s) && i < strlen(input); ++i )
{
  input[i] = ((unsigned __int8)(input[i] & 0xF0) >> 4) | (16 * input[i]);
  input[i] ^= 0x64u;
  if ( input[i] != s[i] )
    dont_be_0 = 0;
}
if ( i != strlen(s) )
  dont_be_0 = 0;
free(input);
return dont_be_0;
```

we will bruteforce for each `char` to match each `byte` in `string`

```python
flag = ''
string = [0x40, 0x77, 0x23, 0x91, 0xB0, 0x72, 0x82, 0x77, 0x63, 0x31, 0xA2, 0x72, 0x21, 0xF2, 0x67, 0x82, 0x91, 0x77, 0x26, 0x91, 0, 0x33, 0x82, 0xC4]
for byte in string:
    for char in range(0x00, 0xff+1): # 0 -> 255
        a = char & 0xfffffff0
        a = a >> 4
        b = (char << 4) & 0xff
        temp = (a | b) % 0xff
        if (temp ^ 0x64) == byte:
            if char:
                flag += chr(char)
            break
print(flag)
```

