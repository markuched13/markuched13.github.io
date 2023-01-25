### Flimsy Proving Grounds Practice

### Difficulty = Easy

### IP Address = 192.168.95.220

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Flimsy]
└─$ nmap -sCV -A 192.168.95.220 -p22,80,3306,43500 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 08:26 WAT
Nmap scan report for 192.168.95.220
Host is up (0.23s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Upright
|_http-server-header: nginx/1.18.0 (Ubuntu)
3306/tcp  open  mysql   MySQL (unauthorized)
43500/tcp open  http    OpenResty web app server
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
|_http-server-header: APISIX/2.8
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.76 seconds
```

Checking out the web server on port 80 returns this page

