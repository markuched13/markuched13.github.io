First thing first we start with scanning the host for open ports using rustscan then use nmap to further enumerate those open ports

`rustscan -a 192.168.108.110`
`nmap -sCV -A -p21,22,80,3000 -oN nmapscan 192.168.144.110`

```
# Nmap 7.92 scan initiated Mon Jan 16 03:34:33 2023 as: nmap -sCV -A -p21,22,80,3000 -oN nmapscan 192.168.144.110
Nmap scan report for 192.168.144.110
Host is up (0.21s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.49.144
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp   open  ssh     OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   3072 9d:3f:eb:1b:aa:9c:1e:b1:30:9b:23:53:4b:cf:59:75 (RSA)
|   256 cd:dc:05:e6:e3:bb:12:33:f7:09:74:50:12:8a:85:64 (ECDSA)
|_  256 a0:90:1f:50:78:b3:9e:41:2a:7f:5c:6f:4d:0e:a1:fa (ED25519)
80/tcp   open  http    Apache httpd 2.4.46 ((Fedora))
|_http-server-header: Apache/2.4.46 (Fedora)
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.txt /web.config /admin/ 
| /comment/reply/ /filter/tips /node/add/ /search/ /user/register/ 
| /user/password/ /user/login/ /user/logout/ /index.php/admin/ 
|_/index.php/comment/reply/
|_http-title: Home | Hacking Articles
|_http-generator: Drupal 9 (https://www.drupal.org)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 16 03:35:20 2023 -- 1 IP address (1 host up) scanned in 46.99 seconds
```

Now there's are 4 services running on the host ftp,ssh,http(80),http(3000).
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/1.png)

FTP allows anonymous login but on trying to list files it hangs
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/2.png)

So next thing is I moved to enumerate port 80 (http)
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/3.png)

But I'm going to have to leave it cause its running a cms which is drupal 9 and the version doesn't have a known vulnerability

Now it feels like the attack surface is going to be from port 3000. Lets goooo!!

On heading to the web page we see that its a site that provides events and issue reporting
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/5.png)

And we have quite some functionalities in it.

So next thing i did was to create an account so that I'll have full access to those functionalities
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/6.png)

And after logging in i decided to check out the New Event Log function 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/7.png)

We see it just requires a username and the event message

Now lets try sending in normal data which will also be intercepted in burp suite


The content of the request headers contains a cookie session id, and userlevel (interesting!)
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/8.png)

But on forwarding the request we see that the response is that only admins are allowed to make an event log 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/9.png)

Now remember the cookie value from the request was a base64 encoded string which when decoded gives `default` 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/10.png)

Lets try base64 encoding `admin` and sending it to the server
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/11.png)
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/12.png)

Now it works and also does redirect us to all the event logs
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/13.png)

Interesting thing is how the message content is been displayed back in the logs

So I tried sending in a url encoded addition arithmetic 7+7 which should give 14
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/14.png)

And it evaluated
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/15.png)

So basically this is a command injection in a node js web server, next thing to do here which is obviously to get a reverse shell 

I grabbed a node js reverse shell from https://revshells.com
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/16.png)

Now urlencoding the payload and sending it to the server
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/17.png)
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/18.png)

And boom!!! We get a shell and we're currently user benjamin
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/19.png)

So its time for priv esc. 

Checking for suid we get a binary that has suid permission set on it `/usr/bin/cp`
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/20.png)

Using https://gtfobins.io we see that its possible to drop an suid perm on another binary if a cp has suid perm set on it.

Lets try it out. The binary i would love to add suid perm set on it is /usr/bin/find but of cause you can use other binary like /usr/bin/bash or something else
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/22.png)

And it worked. Using gtfobins again to get a root shell via suid find 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/23.png)
-
And we're root xD
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Dibble/24.png)

Incase you have any problem on this or I made a mistake please be sure to DM me on discord `Hack.You#9120`

<br> <br>
[Back To Home](../../index.md)
<br>



