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
        result = eval(num1 + op + num2)
        io.sendline(str(result))
        if 'Hero' in io.recvline().decode():
            val = io.recvline()
            break
    return val

io.recvuntil('Can you calculate these for me ?')
io.recvline()
io.recvline()
output = autoSolve()
print(output)
