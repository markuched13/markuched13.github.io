# i = 0
# int(username) + long(i) * 4 != (char(input[i]) ^ 4) + 8

# username = 6b000000790000006d0000007e00000068000000750000006d00000072000000

username = [0x6b, 0x79, 0x6d, 0x7e, 0x68, 0x75, 0x6d, 0x72]    
decoded = []

for num in username:
    value = chr((num - 8) ^ 4)
    decoded.append(value)

print("".join(decoded))

