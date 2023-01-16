First thing first we start with scanning the host for open ports using rustscan then use nmap to further enumerate those open ports

```
# Nmap 7.92 scan initiated Mon Jan 16 03:21:25 2023 as: nmap -sCV -A -p22,25,80,445 -oN nmapscan 192.168.144.71
Nmap scan report for 192.168.144.71
Host is up (0.21s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 db:dd:2c:ea:2f:85:c5:89:bc:fc:e9:a3:38:f0:d7:50 (RSA)
|   256 e3:b7:65:c2:a7:8e:45:29:bb:62:ec:30:1a:eb:ed:6d (ECDSA)
|_  256 d5:5b:79:5b:ce:48:d8:57:46:db:59:4f:cd:45:5d:ef (ED25519)
25/tcp  open  smtp        OpenSMTPD
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.49.144], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
80/tcp  open  http        nginx 1.14.0 (Ubuntu)
|_http-title:         Page not found - FlaskBB        
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: COFFEECORP)
Service Info: Host: bratarina; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h40m00s, deviation: 2h53m13s, median: 0s
| smb2-time: 
|   date: 2023-01-16T02:21:34
|_  start_date: N/A
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: bratarina
|   NetBIOS computer name: BRATARINA\x00
|   Domain name: \x00
|   FQDN: bratarina
|_  System time: 2023-01-15T21:21:35-05:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 16 03:22:18 2023 -- 1 IP address (1 host up) scanned in 53.06 seconds
```

Now there's are 4 services running on the host ssh,smtp,http,smb
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Bratarina/1.png)

Let check out if we can list and connect to shares anonymously in the smb sever
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Bratarina/2.png)

We see there's a share called backups lets connect to it and view the files in it
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Bratarina/3.png)

But from the content there's really nothing there that can help us 

So from the nmapscan we saw that smtp is running on the host now i searched for exploits for opensmtp and got this
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Bratarina/4.png)

On running it we see its requires the target ip, target port, and command to be run
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Bratarina/5.png)

I ran the code again but this time gave it the arguments needed and the command to be run

The command given is a icmp ping request which i'll also be listening for icmp request using tcpdump to know if the target can connect to us 
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Bratarina/6.png)

Now that we know the target can reach us lets get shell.

I'll transfer a file which has a python3  reverse shell content to the target which will be then stored in the /tmp directory

After that i'll give it executable permission then run it 

If its successfull we would get a reverse shell on the target
![1](https://raw.githubusercontent.com/markuched13/markuched13.github.io/main/posts/pg/images/Bratarina/7.png)

And from the result it worked and also granted us root shell

Incase you have any problem on this or I made a mistake please be sure to DM me on discord `Hack.You#9120`

<br> <br>
[Back To Home](../../index.md)
<br>





