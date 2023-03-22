#!/usr/bin/python3
# Author: Hack.You
from pwn import remote
from string import ascii_letters, digits
from Crypto.Util.number import long_to_bytes
from itertools import combinations

def main():
    io = remote("saturn.picoctf.net", "51615")

    e = 65537
    io.recvuntil(b'anger = ')
    c = int(io.readline().decode())
    io.recvuntil(b'envy = ')
    d = int(io.readline().decode())

    ff = [a for a,b in list(factor(d*e-1)) for _ in range(b)] 
    for r in range(2, len(ff)):
        for i in combinations(ff, r):
            p = product(i) + 1
            if p.nbits() != 128 or not is_prime(p):
                continue
            m = long_to_bytes(int(pow(c, d, int(p))))
            if len(m) != 16:
                continue
            io.recvuntil(b'> ')
            io.sendline(m)
            io.interactive()

if __name__ == "__main__":
    try:
        main()
    except EOFError:
        pass
