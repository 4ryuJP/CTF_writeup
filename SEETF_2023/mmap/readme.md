# reversing 

このwriteupは[こちら](https://hackmd.io/@capri/HyIwKvNPh)のwriteupを参考に、自分用に書き残した。

ファイルは以下の通り。
```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1b8773a1392a8591772c71316d7634df816cefa3, for GNU/Linux 3.2.0, stripped

$ pwn checksec chall
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

実行するとpwn問にありがちなメニューが表示される。create noteは何かしらの領域を確保した後、idとアドレスを表示する。writeとreadはその領域に書き込むものと、内容を表示するものだった。

Ghidraで見てみると、どうやら0x1000サイズのmmapで領域が確保されているようだ。このmmapが後々カナリアのリークに絡んでくる。


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

・create note
bool create_note(void)

{
  uint uVar1;
  void *mmap_ptr;
  
  uVar1 = page_count;
  if ((int)page_count < 100) {
    mmap_ptr = mmap((void *)0x0,0x1000,3,0x22,0,0);
    *(void **)(&page_addr + (long)(int)page_count * 8) = mmap_ptr;
    printf("Note created id %d\n",(ulong)page_count);
    printf("Addr of note %d is 0x%llx\n",(ulong)page_count,mmap_ptr);
    page_count = page_count + 1;
  }
  else {
    puts("Note full, cant create anymore!!!!!!!");
  }
  return (int)uVar1 < 100;
}
```
またmainに明らかなスタックオーバーフローのバグがある。
```
undefined8 main(void)

{
  long select;
  long in_FS_OFFSET;
  char input [24];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  puts("Welcome to the SEETF note sandbox!");
  puts("======================================");
  puts("======================================");
  while (flag != 0) {
    menu();
    read(0,input,0x640);
    select = atol(input);
    if (select == 4) {
      flag = 0;
    }
    else if (select < 5) {
      if (select == 3) {
        read();
      }
      else if (select < 4) {
        if (select == 1) {
          create_note();
        }
        else if (select == 2) {
          write();
        }
      }
    }
  }
  setup2();
  puts("Bye!");
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
writeは一見すると0x1000以上書き込めないようになっているが、scanf自体は実行されているためpage_sizeは0x1000以上に上書きされてしまう。これを利用するとreadで0x1000以上読み込むことが可能になる。
```
・writeの一部分抜粋
  printf("idx = ");
  __isoc99_scanf(&%d,&input);
  if (input < page_count) {
    printf("size to write = ");
    __isoc99_scanf(&%d,&page_size + (ulong)input * 4);
    if (*(int *)(&page_size + (ulong)input * 4) < 0x1001) {
      read(0,*(void **)(&page_addr + (ulong)input * 8),(long)*(int *)(&page_size + (ulong)input * 4)
          );
      uVar1 = 1;
    }

・readの一部分抜粋
  printf("idx = ");
  __isoc99_scanf(&%d,&input);
  bVar1 = input < page_count;
  if (bVar1) {
    write(1,*(void **)(&page_addr + (ulong)input * 8),(long)*(int *)(&page_size + (ulong)input * 4))
    ;
  }
```

## exploit
main関数にバグがあるのはわかったが、そのためにはカナリアをリークしなければならない。そこで重要となるのが先ほどのmmapとwriteとreadのバグである。

gdbでカナリアがどの位置にあるのか見てみると
```
gef➤  search-pattern  0xad0c56b0a0f18300
[+] Searching '\x00\x83\xf1\xa0\xb0\x56\x0c\xad' in memory
[+] In (0x7f4f874a8000-0x7f4f874ab000), permission=rw-
  0x7f4f874a8768 - 0x7f4f874a8788  →   "\x00\x83\xf1\xa0\xb0\x56\x0c\xad[...]"
[+] In '[stack]'(0x7ffd909ad000-0x7ffd909ce000), permission=rw-

gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x00000000400000 0x00000000401000 0x00000000000000 r-- /mnt/c/Users/sagit/my_proj/pwn/see/mmap/chall
0x00000000401000 0x00000000402000 0x00000000001000 r-x /mnt/c/Users/sagit/my_proj/pwn/see/mmap/chall
0x00000000402000 0x00000000403000 0x00000000002000 r-- /mnt/c/Users/sagit/my_proj/pwn/see/mmap/chall
0x00000000403000 0x00000000404000 0x00000000002000 r-- /mnt/c/Users/sagit/my_proj/pwn/see/mmap/chall
0x00000000404000 0x00000000405000 0x00000000003000 rw- /mnt/c/Users/sagit/my_proj/pwn/see/mmap/chall
0x007f4f874a8000 0x007f4f874ab000 0x00000000000000 rw-
0x007f4f874ab000 0x007f4f874d3000 0x00000000000000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x007f4f874d3000 0x007f4f87668000 0x00000000028000 r-x /usr/lib/x86_64-linux-gnu/libc.so.6
0x007f4f87668000 0x007f4f876c0000 0x000000001bd000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x007f4f876c0000 0x007f4f876c4000 0x00000000214000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x007f4f876c4000 0x007f4f876c6000 0x00000000218000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
0x007f4f876c6000 0x007f4f876d3000 0x00000000000000 rw-
0x007f4f876d3000 0x007f4f876d5000 0x00000000000000 r-- /usr/lib/x86_64-linux-gnu/libseccomp.so.2.5.3
0x007f4f876d5000 0x007f4f876e3000 0x00000000002000 r-x /usr/lib/x86_64-linux-gnu/libseccomp.so.2.5.3
0x007f4f876e3000 0x007f4f876f0000 0x00000000010000 r-- /usr/lib/x86_64-linux-gnu/libseccomp.so.2.5.3
0x007f4f876f0000 0x007f4f876f1000 0x0000000001d000 --- /usr/lib/x86_64-linux-gnu/libseccomp.so.2.5.3
0x007f4f876f1000 0x007f4f876f2000 0x0000000001d000 r-- /usr/lib/x86_64-linux-gnu/libseccomp.so.2.5.3
0x007f4f876f2000 0x007f4f876f3000 0x0000000001e000 rw- /usr/lib/x86_64-linux-gnu/libseccomp.so.2.5.3
0x007f4f87700000 0x007f4f87702000 0x00000000000000 rw-
0x007f4f87702000 0x007f4f87704000 0x00000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x007f4f87704000 0x007f4f8772e000 0x00000000002000 r-x /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x007f4f8772e000 0x007f4f87739000 0x0000000002c000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x007f4f8773a000 0x007f4f8773c000 0x00000000037000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x007f4f8773c000 0x007f4f8773e000 0x00000000039000 rw- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x007ffd909ad000 0x007ffd909ce000 0x00000000000000 rw- [stack]
0x007ffd909f3000 0x007ffd909f7000 0x00000000000000 r-- [vvar]
0x007ffd909f7000 0x007ffd909f8000 0x00000000000000 r-x [vdso]
```
0x7f4f874a8768 - 0x7f4f874a8788 (この領域に関しては以下 [参考](https://www.slideshare.net/codeblue_jp/master-canary-forging-by-code-blue-2015) )に格納されており、これはちょうどlibcの真上である。つまりmmapで確保した領域がちょうどこの辺りに来れば、writeとreadのバグを利用してカナリアをリークできる。create_noteを何度か実行すると、ちょうど15回目の時にTLSの真上に確保される。これを利用してカナリアをリークする。これでROPの準備が整った。

なお、main関数のreturn前にseccompでopen、mmap、writeのシステムコールのみに制限されているのでシェルは取れない。ROPについてはsolverを参照してほしい。
