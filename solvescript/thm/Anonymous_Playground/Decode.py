#!/usr/bin/python
# Author: Hack.You

word = 'hEzAdCfHzA::hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN'
cipher = word.replace(':', '')
alphabets = []
decode = []

for _ in range(ord('a'), ord('z')+1):
    alphabets.append(chr(_))

for i in range(0, len(cipher), 2):
    first_ = cipher[i]
    second_ = cipher[i+1].lower()

    first_position = ord(first_) - ord('a') + 1
    second_position = ord(second_) - ord('a') + 1

    decoded_position = (first_position + second_position) % 26 
    decoded = alphabets[decoded_position - 1]
    decode.append(decoded)

print(f'Encoded text: {cipher}')
print(f'Alphabet list: {"".join(alphabets)}')
print(f"Decoded: {''.join(decode)[:5]}::{''.join(decode)[5:]}")



