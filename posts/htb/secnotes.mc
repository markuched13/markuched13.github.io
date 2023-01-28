### Secnotes HTB

### Difficulty = Easy

### IP Address = 10.10.10.97

Nmap Scan: 

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ nmap -sCV -A 10.10.10.97 -p80,445 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-28 23:45 WAT
Nmap scan report for 10.10.10.97
Host is up (0.24s latency).

PORT    STATE SERVICE      VERSION
80/tcp  open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
| http-title: Secure Notes - Login
|_Requested resource was login.php
|_http-server-header: Microsoft-IIS/10.0
445/tcp open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2023-01-28T14:45:38-08:00
|_clock-skew: mean: 2h40m03s, deviation: 4h37m13s, median: 0s
| smb2-time: 
|   date: 2023-01-28T22:45:36
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.23 seconds
```

Checking smb we see it doesn't allow anonymous listing of share

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Secnotes]
└─$ smbclient -L 10.10.10.97                                   
Password for [WORKGROUP\mark]:
session setup failed: NT_STATUS_ACCESS_DENIED
```

Lets move on to the web server on port 80


