from base64 import b64decode as d

def xor(data, key):
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def brute(ct):
    possible_keys = [ord(char) for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"]
    
    for key1 in possible_keys:
        for key2 in possible_keys:
            for key3 in possible_keys:
                for key4 in possible_keys:
                    key = bytes([key1, key2, key3, key4])
                    decrypted = xor(ct, key)
                    print(f"Key: {chr(key1)}{chr(key2)}{chr(key3)}{chr(key4)},  Plaintext: {decrypted}")

if __name__ == "__main__":
    b_ct = "PD1VICE4WRgpOVU1KjRGGC45VSkFKFsyBSVcLjQ6SQ=="
    ct = d(b_ct)

    brute(ct)
