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
