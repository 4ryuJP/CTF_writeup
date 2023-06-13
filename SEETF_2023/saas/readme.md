## reversing

問題は以下の通り.この問題はソースコードが同梱されている.

'''
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2f95a46c0648ddb022c28460d3b1c0548edb3084, for GNU/Linux 3.2.0, not stripped

chall.c

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
'''

mmapでshellcodeを実行する領域を確保し,そこに6バイト分書き込む.その後seccompで色々設定しているが,要はopenとreadのシステムコールしか使えない.まずは制約である6バイトをどう解消するかがカギになる.

## exploit

