---
layout: default
title : Sabr CTF 2023 Writeup
---

### CTF Overview

sabrCTF is an online 7-day Jeopardy Capture The Flag competition that mainly features challenges in the topics of reverse engineering and binary exploitation.

### Web Category 

-
### Seikooc: 
So on navigating to the web page I got this:

![1]([https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/1.png])

We can see it just shows cookie and its more of a static page.

![1]([https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/2.png])

Next thing I did was to check the source code maybe we will see anything of interest there but too bad nothing really is there only a word which is embedded in the <img src> tag which is “Find the flag!”

![1]([https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/3.png])

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

![1]([https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/4.png])

We can see there’s a cookie present and its encoded now lets decode the value using cyberchef.

But also if we notice the end of the flag cookie we see its url encoded

So here’s the decoding from cyberchef

![1]([https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/ctf/sabr/images/5.png])

Flag: sabr{c00k13s_sh0uld_4lw4ys_b3_ch3ckEd!!!}


