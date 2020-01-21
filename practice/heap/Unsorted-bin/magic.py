#!/usr/bin/env python2
from pwn import *

sh = process("./magic")
elf = ELF("./magic")
libc = ELF("./libc.so.6")

context.log_level = "debug"


def creat(size, content):
    sh.sendline("1")
    sh.sendline(str(size))
    sh.sendline(str(content))


def edit(index, size, content):
    sh.sendline("2")
    sh.sendline(str(index))
    sh.sendline(str(size))
    sh.sendline(str(content))


def delete(index):
    sh.sendline("3")
    sh.sendline(str(index))

    
