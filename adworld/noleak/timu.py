#! /usr/bin/env python

from pwn import *

sh = process("./timu")
context.log_level = "debug"

def create(size, data):
    sh.sendline("1")
    sh.recvuntil("Size: ")
    sh.sendline(str(size))
    sh.recvuntil("Data: ")
    sh.sendline(data)
    sh.recvuntil("Wellcome To the Heap World\n")
    log.success("Create success!")

def delete(index):
    sh.sendline("2")
    sh.recvuntil("Index: ")
    sh.sendline(str(index))
    sh.recvuntil("Wellcome To the Heap World\n")
    log.success("Delete success!")

def update(index, size, data):
    sh.sendline("3")
    sh.recvuntil("Index: ")
    sh.sendline(str(index))
    sh.recvuntil("Size: ")
    sh.sendline(str(size))
    sh.recvuntil("Data: ")
    sh.sendline(data)
    sh.recvuntil("Wellcome To the Heap World\n")
    log.success("Update success!")

if __name__ == "__main__":
    create(0x80, "aaa")  
    create(0x60, "bbb")
    create(0x10, 'ccc')
    delete(0)
    gdb.attach(sh)

    sh.interactive()
