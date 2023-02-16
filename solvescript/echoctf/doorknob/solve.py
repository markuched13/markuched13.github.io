from pwn import *

io = remote('10.0.30.92', 5903)

# Get menu option
io.recvuntil('menu: Option ')
menu = io.recvline().strip().decode()
print("Menu option found: " +menu)

# Get submenu option
io.recvuntil('submenu: Sub Option')
submenu = io.recvline().strip().decode()
print("Submenu option found: " +submenu)

# Send the corresponding menu & submenu options
io.recvuntil('Choose option or press enter to reprint:')
io.sendline(menu)
io.recvuntil('Choose submenu option or press enter to reprint:')
io.sendline(submenu)
io.recvlineS()

response = io.recv()

if 'ETS' in response:
        success(response)
else:
        print('Hmmmmm flag not found')

    
# python solve.py
