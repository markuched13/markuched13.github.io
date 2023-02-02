### Blocky HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.37

Nmap Scan:

```
# Nmap 7.92 scan initiated Thu Feb  2 01:38:57 2023 as: nmap -sCV -A -p21,22,80 -oN nmapscan 10.10.10.37
Nmap scan report for 10.10.10.37
Host is up (0.25s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5a
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp open  http    Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://blocky.htb
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Feb  2 01:39:15 2023 -- 1 IP address (1 host up) scanned in 18.61 seconds
```

I added blocky.htb to my /etc/hosts file

On going to the web server it shows a page
