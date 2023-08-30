import binascii
from pwn import xor

anthem = bytes(""" Salut à toi pays de nos aïeux, 
        Toi qui les rendais forts, paisibles et joyeux, 
        Cultivant vertu, vaillance, 
        Pour la postérité. 
        Que viennent les tyrans, ton cœur soupire vers la liberté, 
        Togo debout, luttons sans défaillance, 
        Vainquons ou mourons, mais dans la dignité, 
        Grand Dieu, toi seul nous as exaltés, 
        Du Togo pour la prospérité, 
        Togolais viens, bâtissons la cité.""", "utf-8")

with open('output.txt') as h:
    enc_test = binascii.unhexlify(h.readline().strip())
    enc_flag = binascii.unhexlify(h.readline().strip())

blob = xor(enc_test, enc_flag)
flag = xor(blob, anthem[:len(enc_flag)])[:len(enc_flag)]

print(flag)
