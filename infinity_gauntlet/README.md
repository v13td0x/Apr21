psudocode:

```c
COUNTER = 1;
v11 = time(0LL);
srand(v11);
puts("Welcome to the infinity gauntlet!");
puts("If you complete the gauntlet, you'll get the flag!");
while ( 1 )
{
  printf("=== ROUND %d ===\n", (unsigned int)COUNTER);
  v14 = rand();
  X = COUNTER > 49 ? (unsigned __int8)flag[v14 % v6] | ((unsigned __int8)(v14 % v6 + COUNTER) << 8) : rand() % 0x10000; 
  if ( (rand() & 1) != 0 )
  {
    v12 = rand() % 3;
    if ( v12 )
    {
      if ( v12 == 1 )
      {
        EAX = rand();
        printf("foo(%u, ?) = %u\n", (unsigned int)(EAX % 1337), (EAX % 1337) ^ (X + 1) ^ 0x539);
          // X = (a^c^1337)-1
      }
      else
      {
        v13 = rand();
        printf("foo(%u, %u) = ?\n", X ^ (v13 % 1337 + 1) ^ 0x539, (unsigned int)(v13 % 1337));
          // X = a^(b+1)^1337
      }
    }
    else
    {
      v19 = rand();
      printf("foo(?, %u) = %u\n", (unsigned int)(v19 % 1337), X ^ (v19 % 1337 + 1) ^ 0x539);
        // X = c^(b+1)^1337
    }
  }
  else
  {
    v16 = rand();
    if ( (v16 & 3) != 0 )
    {
      v17 = v16 % 4;
      if ( v17 == 1 )
      {
        v24 = rand() % 1337;
        v25 = rand();
        v26 = (unsigned int)(v25 >> 31);
        LODWORD(v26) = v25 % 1337;
        printf("bar(%u, ?, %u) = %u\n", v24, v26, v24 + X * (v25 % 1337 + 1));
          // X = (d-a) / (c+1)
      }
      else if ( v17 == 2 )
      {
        v27 = rand() % 1337;
        v28 = rand();
        v29 = (unsigned int)(v28 >> 31);
        LODWORD(v29) = v28 % 1337;
        printf("bar(%u, %u, ?) = %u\n", v27, v29, v27 + v28 % 1337 * (X + 1));
          // X = ((d - a) / b) -1
      }
      else
      {
        v18 = X <= 0x539 ? rand() % X : rand() % 1337;
        printf("bar(%u, %u, %u) = ?\n", X % v18, v18, X / v18 - 1);
          // NODE: ta thay a - remain of X/b => X = (c+1)* b + a 
      }
    }
    else
    {
      v20 = rand() % 1337;
      v21 = rand();
      printf("bar(?, %u, %u) = %u\n", v20, (unsigned int)(v21 % 1337), X + v20 * (v21 % 1337 + 1));
        // X = d-b*(c+1)
    }
  }
  __isoc99_scanf("%u", &YOUR_ANS);
  if ( YOUR_ANS != X )
    break;
  printf("Correct! Maybe round %d will get you the flag ;)\n", (unsigned int)++COUNTER);
}
puts("Wrong!");
```

