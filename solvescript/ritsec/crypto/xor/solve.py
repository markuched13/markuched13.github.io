#!/usr/bin/python3
# Author: Hack.You

enc_flag = [91,241,101,166,85,192,87,188,110,164,99,152,98,252,34,152,117,164,99,162,107]
x = 'MetaCTF{'
flag = []

for i in range(256):
    if i^ord(x[0]) == enc_flag[0]:
        print('M='+str(i))
    if i^ord(x[1]) == enc_flag[1]:
        print('e='+str(i))
    if i^ord(x[2]) == enc_flag[2]:
        print('t='+str(i))
    if i^ord(x[3]) == enc_flag[3]:
        print('a='+str(i))

key = [22, 148, 17, 199]
print(f'Key = {key}')

for i in range(len(enc_flag)):
    decoded = enc_flag[i] ^ key[i % len(key)]
    flag.append(chr(decoded))

print(f'The flag is: ' + ''.join(flag))
