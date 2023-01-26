### XposedAPI Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.168.134

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/XposedAPI]
└─$ nmap -sCV -A 192.168.168.134 -p22,13337 -oN nmapscan           
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-26 16:05 WAT
Nmap scan report for 192.168.168.134
Host is up (0.29s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
13337/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Remote Software Management API
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.01 seconds
```

Only 2 tcp ports open 

Lets check out the web server
