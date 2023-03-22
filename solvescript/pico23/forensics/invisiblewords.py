#!/usr/bin/python3
# Author: Hack.You

with open('output.bmp', 'rb') as f:
    file = f.read()

file = file[140:]
output = b''.join([file[i:i+2] for i in range(0, len(file), 4)])

with open('output', 'wb') as d:
    d.write(output)
