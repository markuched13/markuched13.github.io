### TakeOver TryHackMe

### Difficulty: Easy

### IP Address = 10.10.149.148

### Domain = futurevera.thm

Description:
```
Hello there,

I am the CEO and one of the co-founders of futurevera.thm. In Futurevera, we believe that the future is in space. We do a lot of space research and write blogs about it. We used to help students with space questions, but we are rebuilding our support.

Recently blackhat hackers approached us saying they could takeover and are asking us for a big ransom. Please help us to find what they can takeover.

Our website is located at https://futurevera.thm

Hint: Don't forget to add the 10.10.149.148 in /etc/hosts for futurevera.thm ; )
```

Nmap Scan:

```
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/B2B/THM/TakeOver]
└─$ nmap -sCV -A futurevera.thm -p22,80,443 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-21 14:12 WAT
Nmap scan report for futurevera.thm (10.10.149.148)
Host is up (0.28s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dd:29:a7:0c:05:69:1f:f6:26:0a:d9:28:cd:40:f0:20 (RSA)
|   256 cb:2e:a8:6d:03:66:e9:70:eb:96:e1:f5:ba:25:cb:4e (ECDSA)
|_  256 50:d3:4b:a8:a2:4d:1d:79:e1:7d:ac:bb:ff:0b:24:13 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://futurevera.thm/
443/tcp open  ssl/http Apache httpd 2.4.41
| tls-alpn: 
|_  http/1.1
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=futurevera.thm/organizationName=Futurevera/stateOrProvinceName=Oregon/countryName=US
| Not valid before: 2022-03-13T10:05:19
|_Not valid after:  2023-03-13T10:05:19
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.31 seconds
```

Checking the web page
![image](https://user-images.githubusercontent.com/113513376/213868620-b59b630b-18b6-4ae2-b67b-c865327fab8a.png)

Fuzzing for sub domains 

