# reversing 

ファイルは以下の通り。
```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1b8773a1392a8591772c71316d7634df816cefa3, for GNU/Linux 3.2.0, stripped

$p pwn checksec chall
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

実行してみると、pwn問にありがちなメニューが表示される。create noteしてみると,明らかにheapとは異なるアドレスとidが表示される。

```
Welcome to the SEETF note sandbox!
======================================
======================================
1. create note
2. write
3. read
4. exit
> 1
Note created id 0
Addr of note 0 is 0x7f2868431000
```
