### Escape Proving Grounds Practice

### IP Address = 192.168.202.113

### Difficulty = Hard

Nmap Scan:

```
└─$ nmap -sCV -A  192.168.202.113 -p22,80,8080
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-13 21:54 WAT
Nmap scan report for 192.168.202.113
Host is up (0.14s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f0:85:61:65:d3:88:ad:49:6b:38:f4:ac:5b:90:4f:2d (RSA)
|   256 05:80:90:92:ff:9e:d6:0e:2f:70:37:6d:86:76:db:05 (ECDSA)
|_  256 c3:57:35:b9:8a:a5:c0:f8:b1:b2:e9:73:09:ad:c7:9a (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Escape
|_http-server-header: Apache/2.4.29 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Escape
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.02 seconds
```

Checking the web server on port 80 & 8080 shows the same thing
