# Sigreturn Oriented Programming

# sigreturn命令(rt_sigreturn)
x86( 173(0xad) ), x64( 15(0xf) )
シグナルを受け取った時の実行状態をスタックに退避し,シグナルハンドラの実行が終わったタイミングで復元させる.
スタックから各レジスタの実行状態を取り出し,レジスタに復元するシステムコール.
構造体は以下の通り.

```
struct sigcontext {
         __u64 r8;
         __u64 r9;
         __u64 r10;
         __u64 r11;
         __u64 r12;
         __u64 r13;
         __u64 r14;
         __u64 r15;
         __u64 rdi;
         __u64 rsi;
         __u64 rbp;
         __u64 rbx;
         __u64 rdx;
         __u64 rax;
         __u64 rcx;
         __u64 rsp;
         __u64 rip;
         __u64 eflags;           /* RFLAGS */
         __u16 cs;
         __u16 gs;
         __u16 fs;
         __u16 __pad0;
         __u64 err;
         __u64 trapno;
         __u64 oldmask;
         __u64 cr2;
         struct _fpstate __user *fpstate;        /* zero when no FPU context */
 #ifdef __ILP32__
         __u32 __fpstate_pad;
 #endif
         __u64 reserved1[8];
};
```

# pwntools

SigreturnFrame()を使って簡単に組むことができる.
関数呼び出しの前にcontext.archでアーキタイプを指定すること.アーキタイプはELF()で得られる情報(?).


# 参考
・システムコール一覧
https://www.mztn.org/lxasm64/x86_x64_table.html
・SROPの詳細
https://inaz2.hatenablog.com/entry/2014/07/30/021123