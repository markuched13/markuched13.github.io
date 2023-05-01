#!/usr/bin/python3
# Author: Hack.You
import base64

encoded = 'RG9IQ1RGe3RyeV90b19iZV9oYWNrdGl2ZV9vbl9kaXNjb3JkX2hlaGVoZWhlaGVoZX0K'

print(base64.b64decode(encoded).strip())
