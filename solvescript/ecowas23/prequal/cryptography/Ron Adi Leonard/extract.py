from Crypto.PublicKey import RSA

public_key = open('public.pem', "rb").read()
key = RSA.importKey(public-key)

print(repr(key))
