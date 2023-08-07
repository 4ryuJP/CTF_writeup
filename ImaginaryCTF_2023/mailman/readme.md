# 分析
,,,
$ file vuln
vuln: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, [略], not stripped

$ pwn checksec vuln
(すべて有効だったので省略)

$ ./libc.so.6
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.1) stable release version 2.35.
,,,

ファイルを実行してみると、おなじみのメニュー画面が出てくる。write letterはidx(bss領域のmem)、letter(mallocのサイズ)、書き込む内容を求める。2は単純にfree、3はチャンクの中身を読み取るもの。バグはこの2と3双方にある。
send letterはmemのアドレスをNULLにしていないし、3はidxが0以上0xf以下かどうかを見ているだけ。つまりfreeした後の中身を見れるので、リーク事態は簡単にできる。
また今回はseccompでopen・read・write・fstat・exitのみ許可されているため、シェルではなくフラグをリークする問題となる。

## リーク
まずlibcのリークを狙っていく。中身は特に問題なく見れるので、重要なのはどうやってlibcのアドレスを出すか。
writeupを見る限り、以下二つの方法がある(内容ほぼ同じだけど)

### 1:tcacheとunsorted bin
まずtcacheとfastbinの基本を押さえておきたい。
・tchaceは0x410以下のチャンクをスレッドごとに格納しており、各スレッドは7つまで保持される。
・fastbinはtcacheから溢れた0x80以下のチャンクを管理する。fastbin以上のサイズはunsortに行く。
unsortに格納されたチャンクはmain_arenaのアドレスが書き込まれる。これをリークすればlibcのアドレスがわかる。戒めとしてもう一度書いておくが、unsortに行くのは0x80より大きいサイズ！！！
また、リークするチャンクの次にサイズの違うチャンクを確保しておく必要がある。これはおそらく管理側でチャンクの結合が行われるためだが、詳しい理屈はよくわかっていない。
また、サイズが任意なので0x410以上のチャンクを確保し、unsortに配置させるのも手。この時、統合を防ぐために違うサイズのチャンクを確保しておくのもポイント。

## フラグリーク
