#!/usr/bin/python3
# Author: Hack.You
import base64

encoded = 'RG9IQ1RGe3RoYXRfd2FzX2Vhc3lfcmlnaHQ/X3JpZ2h0P30K'

print(base64.b64decode(encoded).strip())
