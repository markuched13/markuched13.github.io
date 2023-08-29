from base64 import b64decode as decode
from pwn import xor

def combination():
    for a in range(32, 127):
        for b in range(32, 127):
            yield f"{chr(a)}{chr(b)}"

enc_string = decode('IAUPA1sVCjQ2HhFUHjoyAQs7UBgLGQAAO1AYCxkLDxdFCTogBQ8DXQ==')
known_key = b'Find '

for char_ in combination():
    try:
        key = known_key+char_.encode('utf-8') 
        print(f'Trying key: {key}')
        decoded = xor(key, enc_string)
        if decoded.decode('utf-8').isprintable():
            print(decoded.decode('utf-8'))
    except Exception as e:
        print(e)

# Flag:  flag{xor_puts_the_pun_in_pun_based_flag}
