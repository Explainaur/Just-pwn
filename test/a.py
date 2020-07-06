#! /usr/bin/env python

from pwn import *
context.log_level = "debug"

sh = remote("192.168.4.1", 23)

if __name__ == "__main__":
    print sh.recv()
