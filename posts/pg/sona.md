### Sona Proving Grounds

### Difficulty = Intermediate

### IP Address = 192.168.232.159

Nmap Scan:

```
# Nmap 7.92 scan initiated Fri Feb 24 05:39:13 2023 as: nmap -sCV -A -p23,8081 -oN nmapscan -Pn 192.168.232.159
Nmap scan report for 192.168.232.159
Host is up (0.22s latency).

PORT     STATE SERVICE VERSION
23/tcp   open  telnet?
| fingerprint-strings: 
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     ====================
|     NEXUS BACKUP MANAGER
|     ====================
|     ANSONE Answer question one
|     ANSTWO Answer question two
|     BACKUP Perform backup
|     EXIT Exit
|     HELP Show help
|     HINT Show hints
|     RECOVER Recover admin password
|     RESTORE Restore backup
|     Incorrect
|   NULL, tn3270: 
|     ====================
|     NEXUS BACKUP MANAGER
|     ====================
|     ANSONE Answer question one
|     ANSTWO Answer question two
|     BACKUP Perform backup
|     EXIT Exit
|     HELP Show help
|     HINT Show hints
|     RECOVER Recover admin password
|_    RESTORE Restore backup
8081/tcp open  http    Jetty 9.4.18.v20190429
| http-robots.txt: 2 disallowed entries 
|_/repository/ /service/
|_http-title: Nexus Repository Manager
|_http-server-header: Nexus/3.21.1-01 (OSS)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Feb 24 05:39:45 2023 -- 1 IP address (1 host up) scanned in 31.73 seconds
```

From the scan we see that theres only 2 ports open

We have a telnet service running an a web http server

#### Enumerating Port 23


