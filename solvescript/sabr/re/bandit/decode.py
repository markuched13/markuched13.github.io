array = ['n', 'e', 'g', '{', 'e', 'o', 'n', 'f', 'n', 'q', 'a', 'n', 'c', '_', 'u', 'f', 'h', 'p', '_', 'r', 'e', 'n', '_', 'f', 'r', 'g', '}']

result = []
for char in array:
    if char in ('{', '_', '}'):
        result.append(char)
    else:
        ascii_val = ord(char)
        modified_val = (ascii_val - 84) % 26 + 97
        result.append(chr(modified_val))

print(''.join(result))
