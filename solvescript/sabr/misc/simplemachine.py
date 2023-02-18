#!/usr/bin/python2
from pwn import *

io = remote("13.36.37.184", 9099)

io.sendline("xor x1 4919")

io.sendline("regs")

io.send("win")

io.send("\n")

io.interactive()

io.close()
