#!/usr/bin/env python3 
from pwn import *

target = process("./chall")
#target = remote("tjc.tf", 31601)
gdb.attach(target, gdbscript="b printf")

payload = str(0x80)
target.sendline(payload)

target.interactive()