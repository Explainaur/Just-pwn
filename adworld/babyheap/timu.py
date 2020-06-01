#!  /usr/bin/env    python
from pwn import *

sh = process("./timu")
context.log_level = "debug"
elf = ELF("./timu")
libc = ELF("./libc-2.23.so")
