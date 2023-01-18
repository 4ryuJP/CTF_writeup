# IrisCTF 2023 pwn seek 

```
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

セキュリティは上記の通り.RELROが無効なのでgotを書き換えてフラグを奪取する問題かと予想.
実行するとflagを表示する関数のアドレスと,今いる場所(?)がリークされ,入力を求められる.

```
Your flag is located around 0x556c4ecd0229.
I'm currently at 0x556c4f45d484.
I'll let you write the flag into nowhere!
Where should I seek into? 10
```

この問題はソースコードも配布されている.

```
#include <stdlib.h>
#include <stdio.h>

void win() {
    system("cat /flag");
}

int main(int argc, char *argv[]) {
    // This is just setup
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("Your flag is located around %p.\n", win);

    FILE* null = fopen("/dev/null", "w");
    int pos = 0;
    void* super_special = &win;

    fwrite("void", 1, 4, null);
    printf("I'm currently at %p.\n", null->_IO_write_ptr);
    printf("I'll let you write the flag into nowhere!\n");
    printf("Where should I seek into? ");
    scanf("%d", &pos);
    null->_IO_write_ptr += pos;

    fwrite(&super_special, sizeof(void*), 1, null);
    exit(0);
}

```

/dev/nullをfopenして,ファイルの_IO_write_ptrに書き込んでいるようだ.入力した値は_IO_write_ptrに加算し,flag関数のアドレスをその位置にfwriteで書き込む.


# Exploit

まずソースコードからして,明らかにオーバーフローを起こすような箇所はない.RELROがオフになっていることを考えると,gotを書き換えてflag関数に飛ばすのが解だろう.実際return 0ではなくexit(0)で終了していることから,gotを書き換えるのはexitと考えてよさそう.
そこで必要になるのが以下の二つ.

```
(1)バイナリの先頭アドレス
   このアドレスにexitのgotの相対値を足すと書き換えたい位置に飛ぶ
(2)exitのgot
```

まずは(1)から.以下はgdb-gefでvmmapした時の出力.

```
0x005640894ea000 0x005640894eb000 0x00000000000000 r-- /mnt/c/Users/sagit/my_proj/pwn/seek/chal
0x005640894eb000 0x005640894ec000 0x00000000001000 r-x /mnt/c/Users/sagit/my_proj/pwn/seek/chal win関数の位置
0x005640894ec000 0x005640894ed000 0x00000000002000 r-- /mnt/c/Users/sagit/my_proj/pwn/seek/chal
0x005640894ed000 0x005640894ee000 0x00000000002000 rw- /mnt/c/Users/sagit/my_proj/pwn/seek/chal
0x0056408a9cb000 0x0056408a9ec000 0x00000000000000 rw- [heap]                                   _IO_write_ptrの位置
0x007fdab0ecb000 0x007fdab0eed000 0x00000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x007fdab0eed000 0x007fdab1065000 0x00000000022000 r-x /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x007fdab1065000 0x007fdab10b3000 0x0000000019a000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x007fdab10b3000 0x007fdab10b7000 0x000000001e7000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x007fdab10b7000 0x007fdab10b9000 0x000000001eb000 rw- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x007fdab10b9000 0x007fdab10bf000 0x00000000000000 rw-
0x007fdab10ca000 0x007fdab10cb000 0x00000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x007fdab10cb000 0x007fdab10ee000 0x00000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x007fdab10ee000 0x007fdab10f6000 0x00000000024000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x007fdab10f7000 0x007fdab10f8000 0x0000000002c000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x007fdab10f8000 0x007fdab10f9000 0x0000000002d000 rw- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x007fdab10f9000 0x007fdab10fa000 0x00000000000000 rw-
0x007ffe48dea000 0x007ffe48e0b000 0x00000000000000 rw- [stack]
0x007ffe48ff5000 0x007ffe48ff9000 0x00000000000000 r-- [vvar]
0x007ffe48ff9000 0x007ffe48ffa000 0x00000000000000 r-x [vdso]
```

幸い,バイナリのサイズが小さいおかげでwin関数から0xfffffffff000で&をとった後,0x1000を引いてやればバイナリの先頭アドレスが割り出せる.
(2)のexitのgotはpwntoolのgot["exit"]を使えば相対値が得られるのでこれを足してやればフラグを書き込む位置が割り出せる.

