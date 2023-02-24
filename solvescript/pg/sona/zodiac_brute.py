from pwn import *
import warnings

context.log_level = 'debug'
warnings.filterwarnings("ignore", category=BytesWarning, message="Text is not bytes; assuming ASCII, no guarantees.")


ip = '192.168.232.159'
port = 23

zodiac = ['aries', 'tauras', 'gemini', 'cancer', 'leo', 'virgo', 'libra', 'scorpius', 'sagittarius', 'capricornus', 'aquarius', 'pisces']

# for a in zodiac:
#     upper += a[0].upper()

for i in zodiac:
    io = remote(ip, port)
    io.sendline('HINT')
    io.recvline()
    val = f"{i}"
    io.sendline(val)
    response = io.recvall().decode()
    if 'Incorrect' in response:
        io.close()
    else:
        break



# colour = ['blue', 'yellow', 'green', 'indigo', 'white']

# for i in colour:
#     io = remote(ip, port)
#     msg = f"ANSTWO {i}\n"
#     io.sendline(msg)
#     response = io.recvline()
#     if b'Incorrect' not in response:
#         print(c)
#     break
