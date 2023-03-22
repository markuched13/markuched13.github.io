#!/usr/bin/python3
# Author: Hack.You
import base64

with open('enc_flag', 'r') as f:
    content = f.read()

def solve(val):
    decoded = base64.b64decode(val)
    return decoded

while True:
    try:
        content = solve(content)
        if b'picoCTF' in content:
            print(content)
    except:
        break
