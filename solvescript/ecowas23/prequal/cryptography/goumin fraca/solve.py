from Crypto.Util.number import *

p = 198828927652291316291569791180652465177
q = 315962916257647735873011221555688457883
N = p*q
d = 21178903723966760155190844763458177452716443299090469143032403667752371418657

# convert key*.enc to hex using cyberchef
key0 = bytes.fromhex('0e48d8a6371ca3888f2b8514be91dba5e7ce3b5428c73ef1493f79530cb348be')
enc0 = bytes_to_long(key0)
key1 = bytes.fromhex('5e1c7116f70832d547a734d600715bc677201bb6acf233c12af64f7107134d2b')
enc1 = bytes_to_long(key1)
key2 = bytes.fromhex('0b03a010e0eb7de447f00a215ee4b5d3251e686dd8b4c4113a5a8161e9fde703')
enc2 = bytes_to_long(key2)
key3 = bytes.fromhex('34d14a15a86607da5d16faa5c3ba7224b440edf6c363401d1fa580fe614e1f72')
enc3 = bytes_to_long(key3)

decoded = []
decoded.append(pow(enc0, d, N))
decoded.append(pow(enc1, d, N))
decoded.append(pow(enc2, d, N))
decoded.append(pow(enc3, d, N))

for i in decoded:
    print(long_to_bytes(i).decode(), end='')
