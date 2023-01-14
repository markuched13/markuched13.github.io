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

Next thing I did was to check the source code maybe we will see anything of interest there but too bad nothing really is there only a word which is embedded in the `<img src>` tag which is “Find the flag!”

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

Flag: sabr{S1MPL3_STACK_M4CH1N3}

### Complex machine:


