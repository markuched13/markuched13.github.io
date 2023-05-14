#!/usr/bin/python3
# Author: Hack.You
from pwn import *
import warnings

warnings.filterwarnings('ignore')
context.log_level = 'debug'

io = remote('static-01.heroctf.fr', '8000')

def autoSolve():
    while True:
        cal = io.recvline().decode().strip()
        num1, op, num2 = cal.split()
        if op == '+':
            result = int(num1) + int(num2)
        elif op == '-':
            result = int(num1) - int(num2)
        elif op == '*':
            result = int(num1) * int(num2)
        elif op == '//':
            result = int(num1) // int(num2)  
        else:
            raise ValueError('Invalid operator')
        io.sendline(str(result))
        val = io.recvline().decode()
        if 'Hero' in val:
            print(val)
            break

io.recvuntil('Can you calculate these for me ?')
io.recvline()
io.recvline()
autoSolve()
io.close()
