zh3r0 ctf 2021

**memcmp()**-> **check_password()** ret 0 thi co thong bao "CORRECT PASSWORD"

hàm **check_password** sẽ chia xâu đầu vào (có độ dài 32 bytes) thành 4 khúc, mỗi khúc dài 8 byte. Với mỗi 8 byte, hàm **caculate_block** sẽ thực hiện tính toán và trả về một giá trị kiểu long (8 byte) encoded_password. Giá trị này sẽ được ghi vào vị trí 8 byte tương ứng của mảng trỏ tới bởi encoded_password

```c
__int64 __fastcall check_passw(const char *passw)
{
  const char *v1;
  size_t passw_len;
  __int64 result;
  char *P_encoded_passw;
  const char *v5;
  __int128 encoded_passw[2]; // [rsp+0h] [rbp-58h] BYREF
  char v7; // [rsp+20h] [rbp-38h] BYREF
  // 20h -0h = 20h = 32 = 8*4
  v1 = passw;
  encoded_passw[0] = 0LL;
  encoded_passw[1] = 0LL;
  passw_len = strlen(passw);
  result = 1;
  if (passw_len == 32)      // passw_len = 32
  {
    P_encoded_passw = (char *)encoded_passw;
    do
    {
      v5 = v1;
      // tang 8 bytes len block tiep theo
      P_encoded_passw += 8;
      v1 += 8;
      *((_QWORD *)v4 - 1) = calculate_block((__int64)v5);
      // qword = 8 bytes
    }
    while ( P_encoded_passw != &v7 );
    result = memcmp(encoded_passw, &unk_55560ABB3020, 32); // must be 0
  }
  return result; 
}
______________________________________________
long check_pwssw(char *input)
{
  int iVar1;
  long length;
  long output[4];
  length = strlen(input);
  if (length == 0x20) {
  	for (int i = 0; i < 4; ++i)
  	{
  		output[i] = calculate_block(input);
  		input += 8;
  	}
    isEqual = memcmp(output,&unk_55560ABB3020,0x20);
  }
  return isEqual;
}
```

```c
__int64 __fastcall calculate_block(__int64 input)
{
  __int64 i; // r10
  char v2; // si
  unsigned __int8 eachByte; // r8
  __int64 *Pointer; // rax
  unsigned __int8 v5; // dl
  __int64 output; // [rsp+0h] [rbp-18h] BYREF
  unsigned __int64 v8; // [rsp+8h] [rbp-10h] BYREF
  i = 0LL;
  v2 = 0;
  v8 = __readfsqword(0x28u);
  for ( output = 0LL; ; v2 = output )
  {
    eachByte = *(_BYTE *)(input + i);
    for ( Pointer = &output; ; v2 = *(_BYTE *)Pointer )
    {
      v5 = eachByte;
      Pointer = (__int64 *)((char *)Pointer + 1); // &ouput++ 
      eachByte >>= 1;
      // &output-- = &ouput | (eachByte & 1) << i
      *((_BYTE *)Pointer - 1) = v2 | ((v5 & 1) << i);
      // canary = &output + 8
      if ( &v8 == (unsigned __int64 *)Pointer )
        break;
    }
    if ( ++i == 8 )
      break;
  }
  return output;
}
_____________________________________
char ch = 0;
for(__int64 i = 0; i < 8; ++i)
{
    unsigned __int8 eachByte = *(_BYTE)(input + i);
    __int64 *Pointer = &output;
    // Optimize some vars 
    for(j = 0; j < 8; ++j)
    {
        *((_BYTE *)Pointer) = ch | ((eachByte & 1) << i);
        eachByte >>= 1;
        Pointer = (__int64 *)((char *)Pointer + 1);
        ch = *(_BYTE *)Pointer;
    }
    ch = output;
}
return output;
_____________________________________
long calculate_block(char* input)
{
  int iVar1;
  char eachByte;
  ulong *pointer;
  ulong output = 0
  for (int i = 0; i < 8; ++i)
  {
    pointer = &output;
    eachByte = *(char *)(input + i);
    for (int j = 0; j < 8; ++j)
    {
      *(char *)pointer |= (eachByte & 1) << i;
      (char *)pointer++;
      eachByte = eachByte >> 1;
    }
  }
  return output;
}
```

