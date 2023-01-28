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

Fuzzing for sub domains in http

```
┌──(mark__haxor)-[~/Desktop/B2B/THM/TakeOver]
└─$ ffuf -c -u http://10.10.216.2 -H "Host: FUZZ.futurevera.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.216.2
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.futurevera.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

portal                  [Status: 200, Size: 69, Words: 9, Lines: 2, Duration: 530ms]
payroll                 [Status: 200, Size: 70, Words: 9, Lines: 2, Duration: 215ms]
:: Progress: [110000/110000] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Now i'll edit the /etc/hosts and add the new subdomain

```                                                        
┌──(mark㉿haxor)-[~]
└─$ cat /etc/hosts | grep fut
10.10.216.2     futurevera.thm portal.futurevera.thm payroll.futurevera.thm              
```

Now accesssing the new subdomain
![image](https://user-images.githubusercontent.com/113513376/213890212-67225b5c-b402-4540-afb1-12a90d3ba331.png)

![image](https://user-images.githubusercontent.com/113513376/213890218-a5f989ac-651e-4299-837e-3a667f688332.png)

Too bad we are not allowed to access it 

Now lets fuzz for subdomain in https

```
┌──(mark__haxor)-[~/Desktop/B2B/THM/TakeOver]
└─$ ffuf -c -u https://10.10.216.2 -H "Host: FUZZ.futurevera.thm" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fl 92

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.216.2
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.futurevera.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response lines: 92
________________________________________________

blog                    [Status: 200, Size: 3838, Words: 1326, Lines: 81, Duration: 411ms]
support                 [Status: 200, Size: 1522, Words: 367, Lines: 34, Duration: 607ms]
:: Progress: [110000/110000] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

Adding this also in the /etc/hosts file

```
┌──(mark㉿haxor)-[~]
└─$ cat /etc/hosts | grep fut
10.10.216.2     futurevera.thm portal.futurevera.thm payroll.futurevera.thm blog.futurevera.thm support.futurevera.thm
```

So lets try accessing the new sub domains

Checking the blog subdomain returns something new 
![image](https://user-images.githubusercontent.com/113513376/213890367-659e33d5-8b2a-4a0b-b156-d8e168c4d42b.png)

Now lets also check the support subdomain
![image](https://user-images.githubusercontent.com/113513376/213890383-10dfa23a-57f6-47ed-99b7-fb29f7bbc8e1.png)

Checking the certificates
![image](https://user-images.githubusercontent.com/113513376/213890395-fb88e6cc-40f9-4c72-86b5-9b49dc059608.png)

We have a new subdomain `secrethelpdesk934752.support.futurevera.thm`

Lets add that to /etc/hosts

```
┌──(mark㉿haxor)-[~]
└─$ cat /etc/hosts | grep fut
10.10.216.2     futurevera.thm portal.futurevera.thm payroll.futurevera.thm blog.futurevera.thm support.futurevera.thm secrethelpdesk934752.support.futurevera.thm
```

Accessing it now
![image](https://user-images.githubusercontent.com/113513376/213890438-bb9a3b5f-d4b6-49df-b6c5-ce71a6854463.png)

It leaks the flag needed for the room `flag{beea0d6edfcee06a59b83fb50ae81b2f}`

And we're done 


<br> <br>
[Back To Home](../../index.md)
<br>
