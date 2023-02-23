### Craft Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.175.169

Nmap Scan

```
└─$ nmap -sCV -A 192.168.175.169 -p80 -oN nmapscan                     
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-23 23:35 WAT
Nmap scan report for 192.168.175.169
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-title: Craft
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.55 seconds
```

From the scan we can tell that only one tcp port is open

I'll head over to see what it is
![image](https://user-images.githubusercontent.com/113513376/221046662-3d73f892-cb01-4e17-8966-59ce005fb08c.png)

It doesn't contain anything much
