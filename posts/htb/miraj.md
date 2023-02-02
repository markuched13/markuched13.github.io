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


